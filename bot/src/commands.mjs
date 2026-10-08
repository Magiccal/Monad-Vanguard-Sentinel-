// Slash command definition for /sentinel and the shared formatting helpers.
// Public/reporting commands are available to everyone. Reviewer commands are
// additionally guarded at runtime by Reviewer role membership and a Discord-ID/token map.
import { EmbedBuilder } from 'discord.js';

const LEVEL_CHOICES = [
  { name: 'Informational', value: 'informational' },
  { name: 'Under investigation', value: 'under_investigation' },
  { name: 'Credible threat', value: 'credible_threat' },
  { name: 'Confirmed incident', value: 'confirmed_incident' },
];
const SEVERITY_CHOICES = [
  { name: 'None (informational only)', value: 'none' },
  { name: 'Critical', value: 'critical' },
  { name: 'High', value: 'high' },
  { name: 'Medium', value: 'medium' },
  { name: 'Low', value: 'low' },
];

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
    {
      type: 1,
      name: 'queue',
      description: 'List open private reports (Reviewer role required)',
      options: [],
    },
    {
      type: 1,
      name: 'open',
      description: 'Privately open a report (Reviewer role required)',
      options: [
        { type: 3, name: 'report_id', description: 'Private report ID, e.g. R-0001', required: true, max_length: 32 },
      ],
    },
    {
      type: 1,
      name: 'propose',
      description: 'Propose a public incident from a private report',
      options: [
        { type: 3, name: 'report_id', description: 'Private report ID, e.g. R-0001', required: true, max_length: 32 },
        { type: 3, name: 'level', description: 'Proposed public level', required: true, choices: LEVEL_CHOICES },
        { type: 3, name: 'severity', description: 'Severity, or none for informational', required: true, choices: SEVERITY_CHOICES },
        { type: 3, name: 'title', description: 'Reviewer-written public title', required: true, max_length: 160 },
        { type: 3, name: 'summary', description: 'Reviewer-written public summary', required: true, max_length: 2000 },
        { type: 3, name: 'verification_note', description: 'What evidence supports this level?', required: true, max_length: 500 },
        { type: 3, name: 'advice_1', description: 'First action bullet', required: true, max_length: 300 },
        { type: 3, name: 'reason', description: 'Private reason for this proposal', required: true, max_length: 1000 },
        { type: 3, name: 'public_evidence_numbers', description: 'Comma-separated evidence numbers from /sentinel open', required: false, max_length: 100 },
        { type: 3, name: 'advice_2', description: 'Second action bullet (optional)', required: false, max_length: 300 },
        { type: 3, name: 'advice_3', description: 'Third action bullet (optional)', required: false, max_length: 300 },
      ],
    },
    {
      type: 1,
      name: 'approve',
      description: 'Approve using a proposal UUID or source report number',
      options: [
        { type: 3, name: 'proposal_id', description: 'Proposal UUID or report ID, e.g. R-0001', required: true, max_length: 64 },
      ],
    },
    {
      type: 1,
      name: 'reject',
      description: 'Reject using a proposal UUID or source report number',
      options: [
        { type: 3, name: 'proposal_id', description: 'Proposal UUID or report ID, e.g. R-0001', required: true, max_length: 64 },
        { type: 3, name: 'reason', description: 'Why this proposal is rejected', required: true, min_length: 20, max_length: 1000 },
      ],
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

export function formatReviewerQueue(reports, proposals = []) {
  const open = reports.filter((report) => ['submitted', 'triaged'].includes(report.status) && !report.incidentId);
  const pending = proposals.filter((proposal) => proposal.status === 'pending');
  if (!open.length && !pending.length) return 'No open reports or pending proposals in the reviewer queue.';
  const reportLines = open.slice(0, 12).map((report) => `Report **${report.id}** — ${report.status} (updated ${report.updatedAt})`);
  const proposalLines = pending.slice(0, 8).map((proposal) =>
    `Proposal **${proposal.id}** for ${proposal.reportId} — ${proposal.level}/${proposal.severity ?? 'none'} · approvals ${proposal.approvals}/${proposal.requiredApprovals}`);
  return [...reportLines, ...proposalLines].join('\n').slice(0, 1850);
}

export function formatPrivateReport(report) {
  const lines = [
    `Report **${report.id}** · ${report.status}`,
    `Project: ${report.projectId || 'Not specified'} · Type: ${report.incidentType}`,
    `Submitted: ${report.createdAt}`,
    '',
    'Description:',
    report.description,
    '',
    'Targets:',
    ...(report.targets?.length ? report.targets.map((item) => `• ${item.kind}: ${item.value}`) : ['• None']),
    '',
    'Evidence (use the short number with /sentinel propose only when safe to publish):',
    ...(report.evidence?.length ? report.evidence.map((item, index) => `• ${index + 1}. ${item.kind}: ${item.reference}${item.note ? ` — ${item.note}` : ''}`) : ['• None']),
  ];
  const value = lines.join('\n');
  return value.length <= 1850 ? value : `${value.slice(0, 1840)}\n…[truncated; use the reviewer API for full details]`;
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
