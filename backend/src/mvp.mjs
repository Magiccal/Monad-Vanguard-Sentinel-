import { createHash, randomUUID } from 'node:crypto';
import { DomainError } from './core.mjs';
import { detectSensitiveMaterial, inspectPublicSourceUrl, normalizeAddress, normalizeTransactionHash } from './validation.mjs';
import { normalizeCheckInput, validateProposalIndicators, buildCheckRegistry, matchCheckTarget } from './check.mjs';

const LEVELS = new Set(['informational', 'under_investigation', 'credible_threat', 'confirmed_incident', 'resolved', 'false_alarm']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const INCIDENT_TYPES = new Set(['exploit_hack', 'compromised_account', 'malicious_contract', 'phishing', 'rug_pull', 'not_sure']);
const TARGET_KINDS = new Set(['address', 'transaction_hash', 'url', 'x_handle']);
const EVIDENCE_KINDS = new Set(['transaction', 'link', 'screenshot', 'official_statement']);
export const DISCLAIMER = 'Independent community project · Not affiliated with Monad Foundation · Not financial advice';
const CHECK_NO_MATCH_ADVICE = 'No published Sentinel incident matches this target. This is not a safety guarantee; verify through official channels.';

function fail(status, code, message) { throw new DomainError(status, code, message); }
function object(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(400, 'invalid_input', `${label} must be an object`);
  return value;
}
function optionalText(value, label, max) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !value.trim() || value.trim().length > max) fail(400, 'invalid_input', `${label} must contain 1-${max} characters`);
  if (detectSensitiveMaterial(value)) fail(400, 'sensitive_content', `Remove seed phrases and private keys from ${label}`);
  return value.trim();
}
function text(value, label, min, max) {
  const normalized = optionalText(value, label, max);
  if (!normalized || normalized.length < min) fail(400, 'invalid_input', `${label} must contain ${min}-${max} characters`);
  return normalized;
}
function publicText(value, label, min, max, reporterDiscordId) {
  const normalized = text(value, label, min, max);
  if (/\b(?:https?:\/\/|www\.)/i.test(normalized)) fail(400, 'unsafe_public_text', `${label} must not embed a clickable URL; use approved evidence references`);
  if (normalized.includes(reporterDiscordId)) fail(400, 'private_identity', `${label} must not expose the reporter's Discord ID`);
  return normalized;
}
// Ollie 2026-10-05 23:57: "What you should do" is 1-3 short action bullets, required
// on every public level; false alarm always uses the single bullet "No action needed.".
function adviceBullets(value, level, reporterDiscordId) {
  if (level === 'false_alarm') {
    const items = list(value, 'what-to-do advice', 3);
    if (items.length !== 1 || items[0] !== 'No action needed.') {
      fail(400, 'invalid_input', 'False-alarm publication requires the single advice bullet "No action needed."');
    }
    return ['No action needed.'];
  }
  if (!Array.isArray(value) || value.length < 1 || value.length > 3) {
    fail(400, 'invalid_input', 'what-to-do advice must contain 1-3 short action bullets');
  }
  const seen = new Set();
  return value.map((item) => {
    const normalized = publicText(item, 'what-to-do advice', 10, 300, reporterDiscordId);
    const key = normalized.toLocaleLowerCase();
    if (seen.has(key)) fail(400, 'invalid_input', 'what-to-do advice bullets must be distinct');
    seen.add(key);
    return normalized;
  });
}
function list(value, label, max) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > max) fail(400, 'invalid_input', `${label} must contain at most ${max} items`);
  return value;
}
function httpUrl(value, label) {
  if (typeof value !== 'string' || value.length > 2048) fail(400, 'invalid_input', `${label} must be an HTTP(S) URL`);
  let parsed;
  try { parsed = new URL(value); } catch { fail(400, 'invalid_input', `${label} must be an HTTP(S) URL`); }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    fail(400, 'invalid_input', `${label} must be an HTTP(S) URL without credentials`);
  }
  // Suspicious links may include a query. Keep the exact URL private and never fetch it.
  return parsed.href;
}
function target(value) {
  const item = object(value, 'target');
  if (!TARGET_KINDS.has(item.kind)) fail(400, 'invalid_input', 'Invalid target kind');
  let normalized;
  if (item.kind === 'address') normalized = normalizeAddress(item.value);
  if (item.kind === 'transaction_hash') normalized = normalizeTransactionHash(item.value);
  if (item.kind === 'url') normalized = httpUrl(item.value, 'target URL');
  if (item.kind === 'x_handle') normalized = typeof item.value === 'string' && /^@?[a-zA-Z0-9_]{1,15}$/.test(item.value) ? `@${item.value.replace(/^@/, '')}` : null;
  if (!normalized) fail(400, 'invalid_input', `Invalid ${item.kind} target`);
  return { kind: item.kind, value: normalized };
}
function evidence(value) {
  const item = object(value, 'evidence');
  if (!EVIDENCE_KINDS.has(item.kind)) fail(400, 'invalid_input', 'Invalid evidence kind');
  let reference = null;
  if (item.reference !== undefined) {
    reference = item.kind === 'transaction' ? normalizeTransactionHash(item.reference) : httpUrl(item.reference, 'evidence reference');
    if (!reference) fail(400, 'invalid_input', 'Invalid evidence reference');
  }
  return { id: randomUUID(), kind: item.kind, reference, note: optionalText(item.note, 'evidence note', 500) };
}
function mvpState(state) {
  state.mvp ??= { nextReportNumber: 1, nextIncidentNumber: 1, reports: [], incidents: [], proposals: [], notificationEvents: [] };
  return state.mvp;
}
function readMvp(state) {
  return state.mvp ?? { reports: [], incidents: [], proposals: [], notificationEvents: [] };
}
function find(items, id, label) {
  const found = items.find((item) => item.id === id);
  if (!found) fail(404, 'not_found', `${label} not found`);
  return found;
}
function publicIncident(incident) {
  return {
    id: incident.id, level: incident.level, severity: incident.severity,
    title: incident.title, summary: incident.summary, verificationNote: incident.verificationNote,
    advice: incident.advice, disclaimer: DISCLAIMER,
    evidence: incident.publicEvidence ?? [],
    // Issue #8: indicators are reviewer-selected check targets. They are public
    // data (the check API matches against them), so the public page shows the
    // same list; closed incidents keep them with active: false.
    indicators: (incident.indicators ?? []).map(({ kind, value, active, matchSubdomains }) => ({
      kind, value, active, ...(matchSubdomains !== undefined ? { matchSubdomains } : {}),
    })),
    timeline: incident.versions.map(({ at, level, severity, summary }) => ({ at, level, severity, summary })),
    publishedAt: incident.publishedAt, updatedAt: incident.updatedAt,
    version: incident.versions.length,
    pendingLeadReview: incident.pendingLeadReview === true,
    approvalMode: incident.approvalMode,
    approvalCount: incident.approvalCount ?? 0,
    requiredApprovals: incident.requiredApprovals ?? null,
    ...(incident.leadNotifiedAt ? { leadNotifiedAt: incident.leadNotifiedAt } : {}),
  };
}
function policy(level, severity, previous = null) {
  const priorLeadRequired = previous?.level === 'confirmed_incident' && ['critical', 'high'].includes(previous.severity);
  if (level === 'informational' || level === 'under_investigation') {
    if (previous && ['credible_threat', 'confirmed_incident'].includes(previous.level)) return { count: 2, lead: priorLeadRequired };
    return { count: 1, lead: false };
  }
  if (level === 'credible_threat') return { count: 2, lead: priorLeadRequired };
  if (level === 'confirmed_incident') return { count: 2, lead: priorLeadRequired || ['critical', 'high'].includes(severity) };
  // Ollie 2026-10-03 17:48: medium/low resolved needs any one reviewer; critical/high keeps 2-of-3 with the Lead.
  if (level === 'resolved') return ['critical', 'high'].includes(severity) ? { count: 2, lead: true } : { count: 1, lead: false };
  // Ollie 2026-10-03 17:48: public false_alarm needs 2 of 3 reviewers; the Lead is not required.
  if (level === 'false_alarm') return { count: 2, lead: false };
  fail(409, 'invalid_input', 'Unknown incident level');
}
function approvalState(proposal, reviewerById, demo, rosterFingerprint, atMs) {
  if (proposal.rosterFingerprint !== rosterFingerprint) fail(409, 'reviewer_roster_changed', 'Reviewer roster changed; recreate the proposal under the current roster');
  if (demo) return { ready: true, pendingLeadReview: false };
  const approvals = [...new Set(proposal.approvals.map((item) => item.reviewerId).filter((id) => reviewerById.has(id)))];
  if (approvals.length < proposal.policy.count) return { ready: false, pendingLeadReview: false };
  if (!proposal.policy.lead) return { ready: true, pendingLeadReview: false };
  if (approvals.some((id) => reviewerById.get(id)?.isLead)) return { ready: true, pendingLeadReview: false };
  // Ollie 2026-10-03 17:48: the one-hour fallback clock starts only when the trusted bot
  // confirms it has notified the Lead. That confirmation timestamp is stored on the proposal
  // and later on the published incident. A failed notification never starts the clock.
  const notifiedAtMs = proposal.leadNotifiedAt ? Date.parse(proposal.leadNotifiedAt) : NaN;
  if (Number.isFinite(notifiedAtMs) && atMs - notifiedAtMs >= 60 * 60 * 1000) {
    return { ready: true, pendingLeadReview: true };
  }
  return { ready: false, pendingLeadReview: false };
}

// Issue #8 phase 3: reputation for agent reporters, computed from triage
// outcomes. Transparent formula: +3 per published report, -1 per report whose
// latest proposal was rejected; floor 0. An agent with 2+ rejections and no
// publication is throttled until a reviewer publishes one of its reports.
export function agentReputation(data, agentId) {
  const reports = data.reports.filter((report) => report.reporterAgentId === agentId);
  const published = reports.filter((report) => report.incidentId && report.status === 'published').length;
  const duplicates = reports.filter((report) => report.mergedInto).length;
  const open = reports.filter((report) => !report.incidentId && !report.mergedInto).length;
  const rejected = reports.filter((report) => !report.incidentId && !report.mergedInto
    && data.proposals.some((proposal) => proposal.reportId === report.id && (proposal.rejections?.length ?? 0) > 0)).length;
  const score = Math.max(0, published * 3 - rejected);
  const throttled = rejected >= 2 && published === 0;
  return { reports: reports.length, published, duplicates, open, rejected, score, throttled };
}

export function createMvpService(store, { now = () => new Date().toISOString(), reviewers, agents = [], publicBaseUrl = null } = {}) {
  if (!Array.isArray(reviewers) || ![1, 3].includes(reviewers.length)) throw new Error('MVP requires one demo reviewer or three individually authenticated reviewers');
  const reviewerById = new Map(reviewers.map((reviewer) => [reviewer.id, reviewer]));
  if (reviewerById.size !== reviewers.length || reviewers.some((reviewer) =>
    !reviewer.id || typeof reviewer.id !== 'string' || typeof reviewer.discordId !== 'string' || !/^\d{17,20}$/.test(reviewer.discordId)) ||
    new Set(reviewers.map((reviewer) => reviewer.discordId)).size !== reviewers.length) {
    throw new Error('MVP reviewers require distinct IDs and configured Discord snowflakes');
  }
  // Issue #8 phase 3: registered scout agents file reports through the trusted
  // adapter with their own bearer tokens. Identity is server-side only — the
  // agent never supplies its own id, and publication still requires the same
  // human quorum as any other report.
  if (!Array.isArray(agents)) throw new Error('agents must be an array');
  const agentById = new Map(agents.map((agent) => [agent.id, agent]));
  if (agentById.size !== agents.length || agents.some((agent) =>
    !agent.id || typeof agent.id !== 'string' || !/^[a-z0-9_-]{2,64}$/i.test(agent.id) ||
    typeof agent.name !== 'string' || agent.name.trim().length < 2 || agent.name.length > 100 ||
    typeof agent.token !== 'string' || agent.token.length < 24) ||
    new Set(agents.map((agent) => agent.token)).size !== agents.length) {
    throw new Error('Agent reporters require distinct IDs (2-64 chars), display names (2-100 chars) and distinct bearer tokens of at least 24 characters');
  }
  const demo = reviewers.length === 1;
  if (!demo && (reviewers.some((reviewer) => typeof reviewer.isLead !== 'boolean') || reviewers.filter((reviewer) => reviewer.isLead).length !== 1)) {
    throw new Error('Exactly one Lead reviewer is required');
  }
  const rosterFingerprint = createHash('sha256').update(JSON.stringify(reviewers
    .map(({ id, discordId, isLead }) => ({ id, discordId, isLead: isLead === true }))
    .sort((a, b) => a.id.localeCompare(b.id)))).digest('hex');

  function actor(reviewerId) {
    const reviewer = reviewerById.get(reviewerId);
    if (!reviewer) fail(403, 'unknown_reviewer', 'Configured reviewer identity required');
    return reviewer;
  }
  function noSelfReview(report, reviewer) {
    if (reviewer.discordId && reviewer.discordId === report.reporterDiscordId) fail(403, 'self_review', 'Reviewer cannot approve their own report');
  }
  function publish(mvp, proposal, at, { pendingLeadReview = false } = {}) {
    const report = find(mvp.reports, proposal.reportId, 'Report');
    let incident;
    if (proposal.incidentId) incident = find(mvp.incidents, proposal.incidentId, 'Incident');
    else {
      incident = {
        id: `SEN-${String(mvp.nextIncidentNumber++).padStart(4, '0')}`,
        sourceReportId: report.id, publishedAt: at, versions: [],
      };
      mvp.incidents.push(incident);
      report.incidentId = incident.id;
    }
    incident.level = proposal.level;
    incident.severity = proposal.severity;
    incident.title = proposal.title;
    incident.summary = proposal.summary;
    incident.verificationNote = proposal.verificationNote;
    incident.advice = proposal.advice;
    incident.publicEvidence = proposal.publicEvidence;
    // Issue #8: the registry is rebuilt from published incidents. Omitted
    // indicators carry the previous set over (with matchSubdomains), an
    // explicit [] removes them, and closed incidents (resolved/false_alarm)
    // keep their indicators with active:false so a check returns the closure
    // instead of a stale warning.
    const closed = ['resolved', 'false_alarm'].includes(proposal.level);
    const carriedOver = proposal.indicators === null || proposal.indicators === undefined;
    const indicatorSource = carriedOver
      ? (incident.indicators ?? []).map(({ kind, value, matchSubdomains }) => (
        matchSubdomains === undefined ? { kind, value } : { kind, value, matchSubdomains }))
      : proposal.indicators;
    incident.indicators = indicatorSource.map((item) => ({ ...item, active: !closed }));
    // Ollie 2026-10-18: the public page shows the real approval counts instead
    // of a hardcoded "2 of 3".
    incident.approvalCount = new Set(proposal.approvals.map((item) => item.reviewerId)).size;
    incident.requiredApprovals = demo ? 1 : proposal.policy.count;
    // The check API's weak ETag is derived from this counter; a publication or
    // correction bumps it so cached results refresh (max-age=60).
    mvp.registryVersion = (mvp.registryVersion ?? 0) + 1;
    incident.updatedAt = at;
    incident.approvalMode = demo ? 'demo_single_reviewer' : 'three_reviewer_quorum';
    incident.pendingLeadReview = pendingLeadReview;
    if (proposal.leadNotifiedAt) incident.leadNotifiedAt = proposal.leadNotifiedAt;
    incident.versions.push({ at, level: proposal.level, severity: proposal.severity, summary: proposal.summary,
      proposalId: proposal.id, approvals: proposal.approvals.map(({ reviewerId, at: approvedAt }) => ({ reviewerId, at: approvedAt })) });
    proposal.status = 'published';
    proposal.publishedAt = at;
    report.status = 'published';
    report.updatedAt = at;
    report.history.push({ type: 'published', at, proposalId: proposal.id, incidentId: incident.id });
    // Outbox entries are drafts. No Discord message is sent by this backend.
    if (['credible_threat', 'confirmed_incident', 'resolved', 'false_alarm'].includes(incident.level)) {
      mvp.notificationEvents.push({ id: randomUUID(), channel: 'discord', deliveryState: 'draft', kind: 'incident_published', createdAt: at, incident: publicIncident(incident) });
    }
    return incident;
  }
  function proposalResult(proposal, incident = null) {
    return { id: proposal.id, reportId: proposal.reportId, incidentId: proposal.incidentId, status: proposal.status,
      level: proposal.level, severity: proposal.severity, approvals: proposal.approvals, rejections: proposal.rejections ?? [],
      requiredApprovals: demo ? 1 : proposal.policy.count,
      leadRequired: !demo && proposal.policy.lead,
      leadNotifiedAt: proposal.leadNotifiedAt ?? null,
      approvalMode: demo ? 'demo_single_reviewer' : 'three_reviewer_quorum',
      ...(incident ? { publishedIncident: publicIncident(incident) } : {}) };
  }
  function createProposal(mvp, report, incident, reviewer, input, at) {
    noSelfReview(report, reviewer);
    if (report.status === 'merged') fail(409, 'invalid_transition', 'Merged reports cannot publish an incident');
    if (mvp.proposals.some((item) => item.status === 'pending' && item.reportId === report.id && item.incidentId === (incident?.id ?? null))) {
      fail(409, 'proposal_pending', 'A publication proposal is already pending');
    }
    const data = object(input, 'publication');
    if (!LEVELS.has(data.level)) fail(400, 'invalid_input', 'Unknown incident level');
    if (!incident && data.level === 'resolved') fail(409, 'invalid_transition', 'An unpublished report cannot be resolved');
    if (!incident && data.level === 'false_alarm') fail(409, 'invalid_transition', 'Only a published incident can be marked a false alarm');
    if (incident && ['resolved', 'false_alarm'].includes(incident.level)) fail(409, 'invalid_transition', 'A closed incident cannot be changed through this draft API');
    if (data.level === 'resolved' && !['credible_threat', 'confirmed_incident'].includes(incident?.level)) {
      fail(409, 'invalid_transition', 'Only a published threat or confirmed incident can be resolved');
    }
    const severity = data.level === 'informational' ? null : data.severity;
    if (data.level === 'informational' && data.severity !== null && data.severity !== undefined) fail(400, 'invalid_input', 'Informational severity must be null');
    if (severity !== null && !SEVERITIES.has(severity)) fail(400, 'invalid_input', 'Severity must be critical, high, medium, or low');
    if (['resolved', 'false_alarm'].includes(data.level) && severity !== incident.severity) fail(400, 'invalid_input', 'Closure must retain the published severity');
    const publicEvidenceIds = list(data.publicEvidenceIds ?? incident?.publicEvidence?.map((item) => item.id), 'publicEvidenceIds', 10);
    if (publicEvidenceIds.some((id) => typeof id !== 'string') || new Set(publicEvidenceIds).size !== publicEvidenceIds.length) {
      fail(400, 'invalid_input', 'publicEvidenceIds must be distinct evidence IDs');
    }
    const publicEvidence = publicEvidenceIds.map((id) => {
      const item = report.evidence.find((candidate) => candidate.id === id);
      if (!item) fail(400, 'invalid_input', 'Public evidence ID is not in the source report');
      if (item.kind === 'transaction' && normalizeTransactionHash(item.reference)) {
        return { id: item.id, kind: item.kind, reference: item.reference };
      }
      if (item.kind === 'official_statement' && inspectPublicSourceUrl(item.reference).url) {
        return { id: item.id, kind: item.kind, reference: item.reference };
      }
      fail(400, 'unsafe_public_evidence', 'Only transaction hashes and reviewer-selected HTTPS statement references can be public evidence');
    });
    if (['credible_threat', 'confirmed_incident'].includes(data.level) && publicEvidence.length === 0) {
      fail(400, 'evidence_required', 'Threat and confirmed incident publication requires explicitly approved public evidence');
    }
    // Issue #8: reviewers explicitly select check indicators on the proposal
    // (max 10). They go through the same quorum + Lead gate and are never
    // copied automatically from the private report targets. Omitted field =
    // carry the previous indicators over; explicit [] removes them.
    const indicators = validateProposalIndicators(data.indicators);
    const summary = publicText(data.summary, 'what happened summary', 20, 2000, report.reporterDiscordId);
    if (summary.toLocaleLowerCase() === report.description.toLocaleLowerCase()) {
      fail(400, 'private_report_copy', 'Write a public summary instead of copying the private report description');
    }
    const proposal = {
      id: randomUUID(), reportId: report.id, incidentId: incident?.id ?? null,
      level: data.level, severity, title: publicText(data.title, 'title', 10, 160, report.reporterDiscordId),
      summary,
      verificationNote: publicText(data.verificationNote, 'verification note', 20, 500, report.reporterDiscordId),
      advice: adviceBullets(data.advice, data.level, report.reporterDiscordId),
      reason: text(data.reason, 'reason', 20, 1000),
      publicEvidence,
      indicators,
      status: 'pending', createdAt: at, policy: policy(data.level, severity, incident), rosterFingerprint,
      approvals: [{ reviewerId: reviewer.id, at }], rejections: [],
    };
    mvp.proposals.push(proposal);
    report.history.push({ type: 'publication_proposed', actor: reviewer.id, at, proposalId: proposal.id });
    const result = approvalState(proposal, reviewerById, demo, rosterFingerprint, Date.parse(at));
    if (result.ready) return proposalResult(proposal, publish(mvp, proposal, at, result));
    return proposalResult(proposal);
  }

  return {
    submitDiscord(input, discordUserId) {
      const data = object(input, 'report');
      if (data.reporterId !== undefined || data.reporterName !== undefined || data.reviewerId !== undefined) fail(400, 'invalid_input', 'Reporter and reviewer identity is supplied by the trusted adapter');
      if (typeof discordUserId !== 'string' || !/^\d{17,20}$/.test(discordUserId)) fail(400, 'invalid_input', 'Discord user ID must be a snowflake');
      const description = text(data.description, 'description', 1, 4000);
      const projectId = optionalText(data.projectId, 'projectId', 100);
      const incidentType = data.incidentType ?? 'not_sure';
      if (!INCIDENT_TYPES.has(incidentType)) fail(400, 'invalid_input', 'Unknown incident type');
      const targets = list(data.targets, 'targets', 10).map(target);
      const evidenceItems = list(data.evidence, 'evidence', 10).map(evidence);
      return store.update((state) => {
        const mvp = mvpState(state);
        const at = now();
        const report = {
          id: `R-${String(mvp.nextReportNumber++).padStart(4, '0')}`,
          reporterDiscordId: discordUserId, description, projectId, incidentType,
          targets, evidence: evidenceItems, status: 'submitted', incidentId: null,
          mergedInto: null, createdAt: at, updatedAt: at, reviewerNotifiedAt: null,
          history: [{ type: 'submitted', source: 'discord_bot', at }],
        };
        mvp.reports.push(report);
        return { id: report.id, status: report.status, createdAt: at };
      });
    },
    listDiscordReportStatus(discordUserId) {
      if (typeof discordUserId !== 'string' || !/^\d{17,20}$/.test(discordUserId)) fail(400, 'invalid_input', 'Discord user ID must be a snowflake');
      return store.read((state) => readMvp(state).reports
        .filter((report) => report.reporterDiscordId === discordUserId)
        .map((report) => ({ id: report.id, status: report.status, incidentId: report.incidentId,
          mergedInto: report.mergedInto, createdAt: report.createdAt, updatedAt: report.updatedAt })));
    },
    listUnnotifiedReviewerReports() {
      return store.read((state) => readMvp(state).reports
        .filter((report) => report.status === 'submitted' && !report.reviewerNotifiedAt)
        .map(({ id, createdAt }) => ({ id, createdAt })));
    },
    // Issue #8 phase 3: scout agents file reports through the trusted adapter.
    // Same private intake rules as Discord reports; identity comes from the
    // authenticated agent, never from the payload. Low-reputation agents are
    // throttled until a reviewer publishes one of their reports.
    submitAgentReport(input, agentId) {
      const agent = agentById.get(agentId);
      if (!agent) fail(403, 'unknown_agent', 'Agent reporter is not configured');
      const data = object(input, 'report');
      if (data.reporterId !== undefined || data.reporterName !== undefined || data.reviewerId !== undefined || data.agentId !== undefined) fail(400, 'invalid_input', 'Reporter and reviewer identity is supplied by the trusted adapter');
      const description = text(data.description, 'description', 1, 4000);
      const projectId = optionalText(data.projectId, 'projectId', 100);
      const incidentType = data.incidentType ?? 'not_sure';
      if (!INCIDENT_TYPES.has(incidentType)) fail(400, 'invalid_input', 'Unknown incident type');
      const targets = list(data.targets, 'targets', 10).map(target);
      const evidenceItems = list(data.evidence, 'evidence', 10).map(evidence);
      return store.update((state) => {
        const mvp = mvpState(state);
        const reputation = agentReputation(readMvp(state), agentId);
        if (reputation.throttled) fail(429, 'agent_throttled', 'Too many unconfirmed reports from this agent; a reviewer must publish or clear them first');
        const at = now();
        const report = {
          id: `R-${String(mvp.nextReportNumber++).padStart(4, '0')}`,
          source: 'agent', reporterAgentId: agentId, reporterDiscordId: null,
          description, projectId, incidentType,
          targets, evidence: evidenceItems, status: 'submitted', incidentId: null,
          mergedInto: null, createdAt: at, updatedAt: at, reviewerNotifiedAt: null,
          history: [{ type: 'submitted', source: 'agent', agentId, at }],
        };
        mvp.reports.push(report);
        return { id: report.id, status: report.status, createdAt: at, agentId };
      });
    },
    listAgentReports(agentId) {
      if (!agentById.has(agentId)) fail(403, 'unknown_agent', 'Agent reporter is not configured');
      return store.read((state) => {
        const data = readMvp(state);
        return {
          reports: data.reports
            .filter((report) => report.reporterAgentId === agentId)
            .map((report) => ({ id: report.id, status: report.status, incidentId: report.incidentId,
              mergedInto: report.mergedInto, createdAt: report.createdAt, updatedAt: report.updatedAt })),
          reputation: agentReputation(data, agentId),
        };
      });
    },
    agentProfile(agentId) {
      const agent = agentById.get(agentId);
      if (!agent) fail(403, 'unknown_agent', 'Agent reporter is not configured');
      return store.read((state) => ({
        agent: { id: agent.id, name: agent.name },
        reputation: agentReputation(readMvp(state), agentId),
      }));
    },
    recordReviewerReportNotification(id) {
      return store.update((state) => {
        const report = find(mvpState(state).reports, id, 'Report');
        if (!report.reviewerNotifiedAt) report.reviewerNotifiedAt = now();
        return { id: report.id, reviewerNotifiedAt: report.reviewerNotifiedAt };
      });
    },
    // Reviewer queue: agent reports carry the reporter's live reputation so
    // reviewers can weigh the source; human reports are returned unchanged.
    listReports(reviewerId) {
      actor(reviewerId);
      return store.read((state) => {
        const data = readMvp(state);
        const cache = new Map();
        const reputationFor = (agentId) => {
          if (!cache.has(agentId)) cache.set(agentId, agentReputation(data, agentId));
          return cache.get(agentId);
        };
        return data.reports.map((report) => (report.reporterAgentId
          ? { ...report, reporterReputation: reputationFor(report.reporterAgentId) }
          : report));
      });
    },
    getReport(id, reviewerId) { actor(reviewerId); return store.read((state) => find(readMvp(state).reports, id, 'Report')); },
    triage(id, reviewerId, input = {}) {
      const reviewer = actor(reviewerId);
      const note = optionalText(object(input, 'triage').note, 'triage note', 1000);
      return store.update((state) => {
        const report = find(mvpState(state).reports, id, 'Report');
        noSelfReview(report, reviewer);
        if (report.status !== 'submitted') fail(409, 'invalid_transition', 'Only submitted reports can be triaged');
        const at = now();
        report.status = 'triaged'; report.updatedAt = at;
        report.history.push({ type: 'triaged', actor: reviewer.id, at, note });
        return report;
      });
    },
    mergeDuplicate(id, reviewerId, input) {
      const reviewer = actor(reviewerId);
      const data = object(input, 'merge');
      const intoReportId = text(data.intoReportId, 'intoReportId', 6, 40);
      const reason = text(data.reason, 'reason', 20, 1000);
      return store.update((state) => {
        const mvp = mvpState(state);
        const report = find(mvp.reports, id, 'Report');
        const canonical = find(mvp.reports, intoReportId, 'Canonical report');
        noSelfReview(report, reviewer);
        if (report.id === canonical.id || report.status === 'merged' || report.incidentId || canonical.status === 'merged') fail(409, 'invalid_transition', 'Cannot merge these reports');
        if (mvp.proposals.some((item) => item.reportId === report.id && item.status === 'pending')) fail(409, 'proposal_pending', 'Report has a pending publication');
        const at = now();
        report.status = 'merged'; report.mergedInto = canonical.id; report.updatedAt = at;
        report.history.push({ type: 'merged', actor: reviewer.id, at, intoReportId, reason });
        return report;
      });
    },
    proposeFromReport(id, reviewerId, input) {
      const reviewer = actor(reviewerId);
      return store.update((state) => {
        const mvp = mvpState(state);
        const report = find(mvp.reports, id, 'Report');
        if (report.incidentId) fail(409, 'invalid_transition', 'Use the incident publication route to update an existing incident');
        return createProposal(mvp, report, null, reviewer, input, now());
      });
    },
    proposeFromIncident(id, reviewerId, input) {
      const reviewer = actor(reviewerId);
      return store.update((state) => {
        const mvp = mvpState(state);
        const incident = find(mvp.incidents, id, 'Incident');
        const report = find(mvp.reports, incident.sourceReportId, 'Report');
        return createProposal(mvp, report, incident, reviewer, input, now());
      });
    },
    approveProposal(id, reviewerId) {
      const reviewer = actor(reviewerId);
      return store.update((state) => {
        const mvp = mvpState(state);
        const proposal = find(mvp.proposals, id, 'Proposal');
        if (proposal.status !== 'pending') fail(409, 'invalid_transition', 'Proposal is not pending');
        if (proposal.rosterFingerprint !== rosterFingerprint) fail(409, 'reviewer_roster_changed', 'Reviewer roster changed; recreate the proposal under the current roster');
        const report = find(mvp.reports, proposal.reportId, 'Report');
        noSelfReview(report, reviewer);
        if (proposal.approvals.some((item) => item.reviewerId === reviewer.id)) fail(409, 'duplicate_approval', 'Reviewer already approved');
        const at = now();
        proposal.approvals.push({ reviewerId: reviewer.id, at });
        report.history.push({ type: 'publication_approved', actor: reviewer.id, at, proposalId: proposal.id });
        const result = approvalState(proposal, reviewerById, demo, rosterFingerprint, Date.parse(at));
        if (result.ready) return proposalResult(proposal, publish(mvp, proposal, at, result));
        return proposalResult(proposal);
      });
    },
    rejectProposal(id, reviewerId, input) {
      const reviewer = actor(reviewerId);
      const reason = text(object(input, 'rejection').reason, 'reason', 20, 1000);
      return store.update((state) => {
        const mvp = mvpState(state);
        const proposal = find(mvp.proposals, id, 'Proposal');
        if (proposal.status !== 'pending') fail(409, 'invalid_transition', 'Proposal is not pending');
        if (proposal.rosterFingerprint !== rosterFingerprint) fail(409, 'reviewer_roster_changed', 'Reviewer roster changed; recreate the proposal under the current roster');
        const report = find(mvp.reports, proposal.reportId, 'Report');
        noSelfReview(report, reviewer);
        if (proposal.approvals.some((item) => item.reviewerId === reviewer.id)) fail(409, 'already_approved', 'A reviewer cannot approve and reject the same proposal');
        if (proposal.rejections?.some((item) => item.reviewerId === reviewer.id)) fail(409, 'duplicate_rejection', 'Reviewer already rejected this proposal');
        const at = now();
        proposal.status = 'rejected';
        proposal.rejections ??= [];
        proposal.rejections.push({ reviewerId: reviewer.id, at, reason });
        proposal.rejectedAt = at;
        report.updatedAt = at;
        report.history.push({ type: 'publication_rejected', actor: reviewer.id, at, proposalId: proposal.id, reason });
        return proposalResult(proposal);
      });
    },
    cancelProposal(id, reviewerId, input) {
      const reviewer = actor(reviewerId);
      if (!demo && !reviewer.isLead) fail(403, 'lead_required', 'Only the configured Lead can cancel a pending proposal');
      const cancellationReason = text(object(input, 'cancellation').reason, 'reason', 20, 1000);
      return store.update((state) => {
        const mvp = mvpState(state);
        const proposal = find(mvp.proposals, id, 'Proposal');
        if (proposal.status !== 'pending') fail(409, 'invalid_transition', 'Proposal is not pending');
        const at = now();
        proposal.status = 'cancelled'; proposal.cancelledAt = at; proposal.cancelledBy = reviewer.id; proposal.cancellationReason = cancellationReason;
        const report = find(mvp.reports, proposal.reportId, 'Report');
        report.history.push({ type: 'publication_cancelled', actor: reviewer.id, at, proposalId: proposal.id, reason: cancellationReason });
        return proposalResult(proposal);
      });
    },
    getProposal(id, reviewerId) { actor(reviewerId); return store.read((state) => find(readMvp(state).proposals, id, 'Proposal')); },
    listProposals(reviewerId) {
      actor(reviewerId);
      return store.read((state) => readMvp(state).proposals
        .filter((proposal) => proposal.status === 'pending')
        .map((proposal) => ({
          id: proposal.id, reportId: proposal.reportId, status: proposal.status,
          level: proposal.level, severity: proposal.severity, title: proposal.title,
          approvals: proposal.approvals.length, rejections: proposal.rejections?.length ?? 0,
          requiredApprovals: demo ? 1 : proposal.policy.count,
        })));
    },
    // Trusted-bot discovery feed: pending proposals that have the required non-Lead
    // votes but still wait on the Lead. The Discord adapter uses this to DM the Lead
    // and then confirm the delivery attempt via recordLeadNotification, which is what
    // starts (or deliberately does not start) the one-hour fallback clock.
    listPendingLeadProposals(reviewerId) {
      actor(reviewerId);
      return store.read((state) => readMvp(state).proposals
        .filter((proposal) => {
          if (proposal.status !== 'pending' || !proposal.policy || proposal.policy.lead !== true) return false;
          const approverIds = [...new Set(proposal.approvals.map((item) => item.reviewerId).filter((id) => reviewerById.has(id)))];
          if (approverIds.length < proposal.policy.count) return false;
          return !approverIds.some((id) => reviewerById.get(id)?.isLead);
        })
        .map((proposal) => ({
          id: proposal.id,
          reportId: proposal.reportId,
          incidentId: proposal.incidentId ?? null,
          level: proposal.level,
          severity: proposal.severity,
          title: proposal.title,
          summary: proposal.summary,
          createdAt: proposal.createdAt,
          leadNotifiedAt: proposal.leadNotifiedAt ?? null,
          approvals: [...new Set(proposal.approvals.map((item) => item.reviewerId).filter((id) => reviewerById.has(id)))].length,
          requiredApprovals: proposal.policy.count,
        })));
    },
    // The trusted Discord bot confirms whether it actually notified the Lead. Ollie
    // 2026-10-03 17:48: only a confirmed notification starts the one-hour fallback clock;
    // a failed notification must not start it, so the timestamp stays unset.
    recordLeadNotification(input) {
      const data = object(input, 'lead notification');
      if (typeof data.delivered !== 'boolean') fail(400, 'invalid_input', 'delivered must be a boolean');
      const proposalId = text(data.proposalId, 'proposalId', 6, 64);
      return store.update((state) => {
        const mvp = mvpState(state);
        const proposal = find(mvp.proposals, proposalId, 'Proposal');
        if (proposal.status !== 'pending') fail(409, 'invalid_transition', 'Proposal is not pending');
        if (!proposal.policy?.lead) fail(409, 'lead_not_required', 'This proposal does not require the Lead');
        const at = now();
        if (data.delivered && !proposal.leadNotifiedAt) proposal.leadNotifiedAt = at;
        const report = find(mvp.reports, proposal.reportId, 'Report');
        report.history.push({ type: 'lead_notification_recorded', at, proposalId: proposal.id, delivered: data.delivered });
        return { proposalId: proposal.id, delivered: data.delivered, leadNotifiedAt: proposal.leadNotifiedAt ?? null };
      });
    },
    // Re-evaluates a pending proposal against the current clock so the confirmed
    // one-hour Lead fallback can publish without requiring another vote.
    evaluateProposal(id, reviewerId) {
      actor(reviewerId);
      return store.update((state) => {
        const mvp = mvpState(state);
        const proposal = find(mvp.proposals, id, 'Proposal');
        if (proposal.status !== 'pending') fail(409, 'invalid_transition', 'Proposal is not pending');
        const at = now();
        const result = approvalState(proposal, reviewerById, demo, rosterFingerprint, Date.parse(at));
        if (result.ready) return proposalResult(proposal, publish(mvp, proposal, at, result));
        return proposalResult(proposal);
      });
    },
    listIncidents() { return store.read((state) => readMvp(state).incidents.map(publicIncident)); },
    getIncident(id) { return store.read((state) => publicIncident(find(readMvp(state).incidents, id, 'Incident'))); },
    // Issue #8 phase 1: keyless check API read path. Returns only data that is
    // already on the public incidents page; an unpublished target gets level
    // "none", which is never a safety guarantee.
    checkTarget(input) {
      const checked = normalizeCheckInput(input);
      return store.read((state) => {
        const registry = buildCheckRegistry(readMvp(state).incidents.map(publicIncident));
        const ranked = matchCheckTarget(registry, checked);
        const top = ranked[0] ?? null;
        return {
          target: checked,
          matched: Boolean(top),
          level: top ? top.level : 'none',
          severity: top ? top.severity : null,
          advice: top ? top.advice : [CHECK_NO_MATCH_ADVICE],
          verifiedAt: top ? top.verifiedAt : null,
          incidentId: top ? top.incidentId : null,
          incidentUrl: top && publicBaseUrl ? `${publicBaseUrl.replace(/\/$/, '')}/mvp.html#${top.incidentId}` : null,
          matchedIndicator: top ? { kind: top.kind, value: top.value, active: top.active } : null,
          matches: ranked.map((entry) => ({
            incidentId: entry.incidentId, level: entry.level, severity: entry.severity,
            matchedIndicator: { kind: entry.kind, value: entry.value, active: entry.active },
          })),
          checkedAt: now(),
          disclaimer: DISCLAIMER,
        };
      });
    },
    getCheckRegistryVersion() {
      return store.read((state) => readMvp(state).registryVersion ?? 0);
    },
    listNotificationEvents(reviewerId) { actor(reviewerId); return store.read((state) => readMvp(state).notificationEvents); },
  };
}
