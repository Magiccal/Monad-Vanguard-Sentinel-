// Slash command definition for /sentinel and the shared formatting helpers.
// The four commands match the team plan (Ollie, 2026-10-06):
//   /sentinel report    - submit a private report (stays private until a reviewer opens it)
//   /sentinel check     - look up a published incident by SEN-#### (or list the latest)
//   /sentinel status    - minimal status of one of your own reports (R-####)
//   /sentinel myreports - minimal status of all your own reports
import { EmbedBuilder } from 'discord.js';

export const INCIDENT_TYPE_CHOICES = [
  { name: 'Exploit / hack', value: 'exploit_hack' },
  { name: 'Compromised account', value: 'compromised_account' },
  { name: 'Malicious contract', value: 'malicious_contract' },
  { name: 'Phishing', value: 'phishing' },
  { name: 'Rug pull', value: 'rug_pull' },
  { name: 'Not sure', value: 'not_sure' },
];

export const sentinelCommand = {
  name: 'sentinel',
  description: 'Community security sentinel (reports stay private until a reviewer opens them)',
  options: [
    {
      type: 1, // SUB_COMMAND
      name: 'report',
      description: 'Submit a private security report',
      options: [
        { type: 3, name: 'description', description: 'What happened? Do not paste seeds or private keys.', required: true, max_length: 4000 },
        { type: 3, name: 'project', description: 'Affected project name (optional)', required: false, max_length: 100 },
        { type: 3, name: 'type', description: 'Incident type (optional)', required: false, choices: INCIDENT_TYPE_CHOICES },
        { type: 3, name: 'target_url', description: 'Suspicious URL (optional, stored privately, never fetched)', required: false, max_length: 500 },
        { type: 3, name: 'target_address', description: 'Suspicious contract or wallet address (optional)', required: false, max_length: 100 },
        { type: 3, name: 'evidence_url', description: 'HTTPS evidence link or transaction hash (optional)', required: false, max_length: 500 },
      ],
    },
    {
      type: 1,
      name: 'check',
      description: 'Look up a published incident by ID (SEN-####), or list the latest incidents',
      options: [
        { type: 3, name: 'incident_id', description: 'Public incident ID, e.g. SEN-0001 (optional)', required: false, max_length: 32 },
      ],
    },
    {
      type: 1,
      name: 'status',
      description: 'Check the private status of one of your reports',
      options: [
        { type: 3, name: 'report_id', description: 'Your report ID, e.g. R-0001', required: true, max_length: 32 },
      ],
    },
    {
      type: 1,
      name: 'myreports',
      description: 'List the minimal status of all reports you submitted',
      options: [],
    },
  ],
};

export function formatReportSubmitted(created) {
  return [
    '✅ Report received and kept private.',
    `Report ID: **${created.id}** (status: ${created.status})`,
    'A reviewer must open it before anything is published. Use `/sentinel status report_id:' + created.id + '` to follow up.',
    'Reminder: never paste seed phrases or private keys anywhere.',
  ].join('\n');
}

export function formatReportRows(reports) {
  if (!reports.length) return 'You have no reports yet. Submit one with `/sentinel report`.';
  return reports.map((report) => {
    const linked = report.mergedInto ? ` (merged into ${report.mergedInto})` : report.incidentId ? ` (published as ${report.incidentId})` : '';
    return `**${report.id}** — ${report.status}${linked} (updated ${report.updatedAt})`;
  }).join('\n');
}

const LEVEL_COLORS = {
  informational: 0x808080,
  under_investigation: 0xe67e22,
  credible_threat: 0xe74c3c,
  confirmed_incident: 0xc0392b,
  resolved: 0x2ecc71,
  false_alarm: 0x34495e,
};

export function incidentEmbed(incident) {
  const severity = incident.severity ? String(incident.severity).toUpperCase() : 'N/A';
  const bullets = (incident.advice ?? []).map((line) => `• ${line}`).join('\n');
  return new EmbedBuilder()
    .setTitle(`${incident.id} — ${incident.title}`)
    .setColor(LEVEL_COLORS[incident.level] ?? 0x808080)
    .addFields(
      { name: 'Level', value: String(incident.level), inline: true },
      { name: 'Severity', value: severity, inline: true },
      { name: 'What happened', value: String(incident.summary).slice(0, 1024) },
      { name: 'What you should do', value: bullets.slice(0, 1024) || '—' },
    )
    .setFooter({ text: `${incident.disclaimer} · Not financial advice` })
    .setTimestamp(new Date(incident.updatedAt ?? Date.now()));
}

export function formatIncidentLine(incident) {
  const severity = incident.severity ? ` / ${incident.severity}` : '';
  return `**${incident.id}** [${incident.level}${severity}] ${incident.title}`;
}
