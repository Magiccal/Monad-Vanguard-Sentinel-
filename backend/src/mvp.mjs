import { createHash, randomUUID } from 'node:crypto';
import { DomainError } from './core.mjs';
import { detectSensitiveMaterial, inspectPublicSourceUrl, normalizeAddress, normalizeTransactionHash } from './validation.mjs';

const LEVELS = new Set(['informational', 'under_investigation', 'credible_threat', 'confirmed_incident', 'resolved', 'false_alarm']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low']);
const INCIDENT_TYPES = new Set(['exploit_hack', 'compromised_account', 'malicious_contract', 'phishing', 'rug_pull', 'not_sure']);
const TARGET_KINDS = new Set(['address', 'transaction_hash', 'url', 'x_handle']);
const EVIDENCE_KINDS = new Set(['transaction', 'link', 'screenshot', 'official_statement']);
const DISCLAIMER = 'Independent community project · Not affiliated with Monad Foundation · Not financial advice';

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
    timeline: incident.versions.map(({ at, level, severity, summary }) => ({ at, level, severity, summary })),
    publishedAt: incident.publishedAt, updatedAt: incident.updatedAt,
    version: incident.versions.length,
    pendingLeadReview: incident.pendingLeadReview === true,
    approvalMode: incident.approvalMode,
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

export function createMvpService(store, { now = () => new Date().toISOString(), reviewers } = {}) {
  if (!Array.isArray(reviewers) || ![1, 3].includes(reviewers.length)) throw new Error('MVP requires one demo reviewer or three individually authenticated reviewers');
  const reviewerById = new Map(reviewers.map((reviewer) => [reviewer.id, reviewer]));
  if (reviewerById.size !== reviewers.length || reviewers.some((reviewer) =>
    !reviewer.id || typeof reviewer.id !== 'string' || typeof reviewer.discordId !== 'string' || !/^\d{17,20}$/.test(reviewer.discordId)) ||
    new Set(reviewers.map((reviewer) => reviewer.discordId)).size !== reviewers.length) {
    throw new Error('MVP reviewers require distinct IDs and configured Discord snowflakes');
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
      level: proposal.level, severity: proposal.severity, approvals: proposal.approvals,
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
    const summary = publicText(data.summary, 'what happened summary', 20, 2000, report.reporterDiscordId);
    if (summary.toLocaleLowerCase() === report.description.toLocaleLowerCase()) {
      fail(400, 'private_report_copy', 'Write a public summary instead of copying the private report description');
    }
    const proposal = {
      id: randomUUID(), reportId: report.id, incidentId: incident?.id ?? null,
      level: data.level, severity, title: publicText(data.title, 'title', 10, 160, report.reporterDiscordId),
      summary,
      verificationNote: publicText(data.verificationNote, 'verification note', 20, 500, report.reporterDiscordId),
      advice: publicText(data.advice, 'what-to-do advice', 10, 500, report.reporterDiscordId),
      reason: text(data.reason, 'reason', 20, 1000),
      publicEvidence,
      status: 'pending', createdAt: at, policy: policy(data.level, severity, incident), rosterFingerprint,
      approvals: [{ reviewerId: reviewer.id, at }],
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
          mergedInto: null, createdAt: at, updatedAt: at,
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
    listReports(reviewerId) { actor(reviewerId); return store.read((state) => readMvp(state).reports); },
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
    listNotificationEvents(reviewerId) { actor(reviewerId); return store.read((state) => readMvp(state).notificationEvents); },
  };
}
