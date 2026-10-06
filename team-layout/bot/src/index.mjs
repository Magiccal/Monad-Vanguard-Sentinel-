// Sentinel Discord adapter (MVP). Responsibilities:
//   1. Serve the four /sentinel subcommands (report / check / status / myreports).
//   2. Post newly published incidents (outbox drafts) to the public #sentinel-alerts channel.
//   3. DM the Lead when a proposal is waiting on their approval and confirm the delivery
//      attempt via POST /v1/discord/lead-notifications (delivered true ONLY after the DM
//      was actually sent; a failed DM confirms delivered:false so the fallback clock never
//      starts on a failed notification — Ollie, 2026-10-03).
// The backend never sends Discord messages itself; this adapter is the only delivery path.

// Proxy support: when HTTPS_PROXY/HTTP_PROXY is set, route (a) discord.js REST through
// undici's ProxyAgent (global dispatcher) and (b) the gateway WebSocket through an
// https-proxy-agent injected into every `ws` connection. @discordjs/ws instantiates the
// ws WebSocket with no injection point, so patch the ws exports BEFORE discord.js loads.
// Both parts are no-ops when no proxy is configured (default deployment is direct).
if (process.env.HTTPS_PROXY || process.env.HTTP_PROXY) {
  const proxyUrl = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
  const { setGlobalDispatcher, ProxyAgent } = await import('undici');
  setGlobalDispatcher(new ProxyAgent(proxyUrl));
  const { createRequire } = await import('module');
  const wsCjs = createRequire(import.meta.url)('ws'); // CJS exports = the WebSocket function
  const { HttpsProxyAgent } = await import('https-proxy-agent');
  const proxyAgent = new HttpsProxyAgent(proxyUrl);
  class ProxyWebSocket extends wsCjs.WebSocket {
    constructor(address, protocols, options) {
      super(address, protocols, { ...options, agent: proxyAgent });
    }
  }
  // @discordjs/ws captures ws.WebSocket (the self-referencing property on the CJS
  // exports) into its WebSocketConstructor at load time, so patch before discord.js
  // is imported (it is dynamically imported right after this block).
  wsCjs.WebSocket = ProxyWebSocket;
}

const { Client, Events, GatewayIntentBits, MessageFlags } = await import('discord.js');
import { config } from './config.mjs';
import { backend } from './backend.mjs';
const { formatIncidentLine, formatReportRows, formatReportSubmitted, incidentEmbed } = await import('./commands.mjs');

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// In-memory dedupe. The MVP adapter runs as a single process; restarting re-reads the
// backend feeds, so at most one duplicate alert post or Lead DM can happen after a restart.
const postedIncidentVersions = new Set();
const leadNotifiedProposals = new Set();

client.once(Events.ClientReady, (ready) => {
  console.log(`[sentinel-bot] logged in as ${ready.user.tag}`);
  setInterval(() => void runSafely('alerts', deliverAlerts), config.pollIntervalMs);
  setInterval(() => void runSafely('lead', notifyLead), config.pollIntervalMs);
  void runSafely('alerts', deliverAlerts);
  void runSafely('lead', notifyLead);
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (!interaction.isChatInputCommand() || interaction.commandName !== 'sentinel') return;
    await handleSentinel(interaction);
  } catch (error) {
    console.error('[sentinel-bot] interaction failed:', error);
    const message = `Something went wrong: ${error.code ?? error.message}`;
    if (interaction.deferred || interaction.replied) await interaction.followUp({ content: message, flags: MessageFlags.Ephemeral }).catch(() => {});
    else await interaction.reply({ content: message, flags: MessageFlags.Ephemeral }).catch(() => {});
  }
});

async function handleSentinel(interaction) {
  const subcommand = interaction.options.getSubcommand();
  const reporterId = interaction.user.id;
  switch (subcommand) {
    case 'report': {
      const body = { description: interaction.options.getString('description', true) };
      const project = interaction.options.getString('project');
      const type = interaction.options.getString('type');
      const targetUrl = interaction.options.getString('target_url');
      const targetAddress = interaction.options.getString('target_address');
      const evidenceUrl = interaction.options.getString('evidence_url');
      if (project) body.projectId = project;
      if (type) body.incidentType = type;
      const targets = [];
      if (targetUrl) targets.push({ kind: 'url', value: targetUrl });
      if (targetAddress) targets.push({ kind: 'address', value: targetAddress });
      if (targets.length) body.targets = targets;
      if (evidenceUrl) {
        body.evidence = [{ kind: /^(0x)?[0-9a-f]{64}$/i.test(evidenceUrl) ? 'transaction' : 'link', reference: evidenceUrl }];
      }
      const created = await backend.submitReport(reporterId, body);
      await interaction.reply({ content: formatReportSubmitted(created), flags: MessageFlags.Ephemeral });
      return;
    }
    case 'check': {
      const id = interaction.options.getString('incident_id');
      if (id) {
        const incident = await backend.listIncidents().then(({ incidents }) => incidents.find((item) => item.id.toUpperCase() === id.toUpperCase()));
        if (!incident) {
          await interaction.reply({ content: `No published incident found for ${id}. Public IDs look like SEN-0001.`, flags: MessageFlags.Ephemeral });
          return;
        }
        await interaction.reply({ embeds: [incidentEmbed(incident)] });
        return;
      }
      const { incidents } = await backend.listIncidents();
      if (!incidents.length) {
        await interaction.reply({ content: 'No incidents have been published yet.', flags: MessageFlags.Ephemeral });
        return;
      }
      const lines = incidents.slice(-5).reverse().map(formatIncidentLine);
      await interaction.reply({ content: ['Latest published incidents:', ...lines].join('\n'), flags: MessageFlags.Ephemeral });
      return;
    }
    case 'status': {
      const id = interaction.options.getString('report_id', true);
      const { reports } = await backend.reportStatus(reporterId);
      const mine = reports.find((report) => report.id.toUpperCase() === id.toUpperCase());
      if (!mine) {
        await interaction.reply({ content: `No report ${id} is associated with your Discord account. Report contents stay private; the bot can only see minimal status.`, flags: MessageFlags.Ephemeral });
        return;
      }
      await interaction.reply({ content: formatReportRows([mine]), flags: MessageFlags.Ephemeral });
      return;
    }
    case 'myreports': {
      const { reports } = await backend.reportStatus(reporterId);
      await interaction.reply({ content: formatReportRows(reports), flags: MessageFlags.Ephemeral });
      return;
    }
    default:
  }
}

// Post newly published incidents (reviewer-approved) to #sentinel-alerts with level,
// severity, "What you should do" bullets and the unified disclaimer footer.
async function deliverAlerts() {
  const { events } = await backend.notificationOutbox();
  const drafts = events.filter((event) => event.channel === 'discord' && event.kind === 'incident_published' && event.incident);
  let newestFirst = [...drafts].reverse();
  for (const event of newestFirst) {
    const key = `${event.incident.id}#v${event.incident.version}`;
    if (postedIncidentVersions.has(key)) continue;
    const channel = await client.channels.fetch(config.alertChannelId);
    await channel.send({ embeds: [incidentEmbed(event.incident)] });
    postedIncidentVersions.add(key);
  }
}

// DM the Lead about every proposal that is waiting on their approval, then confirm the
// delivery result so the one-hour fallback clock is handled exactly per the agreed rules.
async function notifyLead() {
  const { proposals } = await backend.pendingLeadProposals();
  for (const proposal of proposals) {
    if (leadNotifiedProposals.has(proposal.id)) continue;
    let delivered = false;
    try {
      const user = await client.users.fetch(config.leadDiscordId);
      const severity = proposal.severity ? ` (severity: ${proposal.severity})` : '';
      await user.send([
        `🛡️ A publication proposal needs your Lead approval: **${proposal.title}**${severity}`,
        `Level: ${proposal.level} · Approvals: ${proposal.approvals}/${proposal.requiredApprovals}`,
        `Summary: ${proposal.summary}`,
        `Proposal ID: ${proposal.id}`,
        'Open the reviewer tooling to approve or cancel. If you do not respond within one hour of this message, the agreed fallback publishes it marked `pendingLeadReview`.',
      ].join('\n'));
      delivered = true;
    } catch (error) {
      console.error('[sentinel-bot] Lead DM failed:', error.message);
    }
    // delivered:true only after a real DM; false never starts the fallback clock.
    await backend.confirmLeadNotification(proposal.id, delivered);
    leadNotifiedProposals.add(proposal.id);
  }
}

async function runSafely(loop, fn) {
  try {
    await fn();
  } catch (error) {
    console.error(`[sentinel-bot] ${loop} loop failed:`, error.message);
  }
}

client.login(config.discordToken);
