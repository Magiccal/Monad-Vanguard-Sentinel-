import { randomUUID } from 'node:crypto';

export class DomainError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

function fail(status, code, message) {
  throw new DomainError(status, code, message);
}

function object(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(400, 'invalid_input', `${name} must be an object`);
  }
  return value;
}

function string(value, name, min, max) {
  if (typeof value !== 'string' || value.trim().length < min || value.trim().length > max) {
    fail(400, 'invalid_input', `${name} must contain ${min}-${max} characters`);
  }
  return value.trim();
}

function reason(value) {
  return string(value, 'reason', 20, 1000);
}

function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value)) {
    fail(400, 'invalid_input', 'contractAddress must be a 20-byte hex address');
  }
  return value.toLowerCase();
}

function evidence(value, at, actor) {
  const item = object(value, 'evidence item');
  const note = string(item.note, 'evidence note', 10, 500);
  if (item.kind === 'transaction') {
    if (typeof item.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(item.txHash)) {
      fail(400, 'invalid_input', 'transaction evidence requires a 32-byte txHash');
    }
    return { id: randomUUID(), kind: 'transaction', txHash: item.txHash.toLowerCase(), note, addedAt: at, addedBy: actor };
  }
  if (item.kind === 'public_source') {
    let url;
    try { url = new URL(item.url); } catch { fail(400, 'invalid_input', 'source URL is invalid'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.href.length > 2048) {
      fail(400, 'invalid_input', 'source URL must be HTTPS without credentials, query, or fragment');
    }
    return { id: randomUUID(), kind: 'public_source', url: url.href, note, addedAt: at, addedBy: actor };
  }
  fail(400, 'invalid_input', 'evidence kind must be transaction or public_source');
}

function findReport(state, id) {
  const report = state.reports.find((item) => item.id === id);
  if (!report) fail(404, 'not_found', 'Report not found');
  return report;
}

function findWatchTarget(state, id) {
  const target = (state.watchlist ?? []).find((item) => item.id === id);
  if (!target) fail(404, 'not_found', 'Watch target not found');
  return target;
}

function requireStatus(report, status) {
  if (report.status !== status) {
    fail(409, 'invalid_transition', `Report must be ${status}; it is ${report.status}`);
  }
}

function event(report, type, actor, at, details = {}) {
  report.history.push({ type, actor, at, ...details });
  report.updatedAt = at;
}

function publicAlert(report) {
  if (!['verified', 'retracted'].includes(report.status)) return null;
  const latest = report.alertVersions.at(-1);
  const approvedEvidenceIds = new Set(report.publicEvidenceIds ?? []);
  const observation = report.observations?.at(-1);
  const publicFindings = observation?.findings.filter((item) => approvedEvidenceIds.has(item.evidenceId)) ?? [];
  return {
    id: report.id,
    status: report.status,
    classification: latest.classification ?? report.classification ?? 'credible_threat',
    chainId: report.chainId,
    contractAddress: report.contractAddress,
    title: latest.title,
    advice: latest.advice,
    evidence: report.evidence.filter((item) => approvedEvidenceIds.has(item.id)).map(({ addedBy, ...item }) => item),
    onchainObservation: publicFindings.length ? { ...observation, findings: publicFindings } : null,
    publishedAt: report.alertVersions[0].at,
    updatedAt: report.updatedAt,
    version: report.alertVersions.length,
    corrections: report.alertVersions.slice(1).map(({ at, reason: correctionReason, title, advice, classification }, index) => ({
      version: index + 2, at, reason: correctionReason, title, advice, classification,
    })),
    ...(report.retraction ? { retraction: report.retraction } : {}),
  };
}

function enqueueNotification(state, report, kind, at) {
  const alert = publicAlert(report);
  state.notificationEvents ??= [];
  state.notificationEvents.push({
    id: randomUUID(), kind, createdAt: at, deliveryState: 'draft',
    alertId: alert.id, version: alert.version, status: alert.status,
    classification: alert.classification, chainId: alert.chainId,
    contractAddress: alert.contractAddress, title: alert.title,
    advice: alert.advice, alertPath: `/v1/alerts/${alert.id}`,
  });
}

export function createSentinel(store, { now = () => new Date().toISOString() } = {}) {
  return {
    submit(input) {
      const data = object(input, 'report');
      const reporterId = string(data.reporterId, 'reporterId', 2, 80);
      const title = string(data.title, 'title', 10, 160);
      const description = string(data.description, 'description', 20, 2000);
      if (!Number.isSafeInteger(data.chainId) || data.chainId <= 0) {
        fail(400, 'invalid_input', 'chainId must be a positive integer');
      }
      const contractAddress = address(data.contractAddress);
      if (!Array.isArray(data.evidence) || data.evidence.length < 1 || data.evidence.length > 10) {
        fail(400, 'invalid_input', 'evidence must contain 1-10 items');
      }
      const at = now();
      const report = {
        id: randomUUID(), status: 'submitted', classification: 'informational', reporterId, title, description,
        chainId: data.chainId, contractAddress,
        evidence: data.evidence.map((item) => evidence(item, at, reporterId)),
        createdAt: at, updatedAt: at, reviewerId: null,
        decision: null, alertVersions: [], retraction: null, observations: [], publicEvidenceIds: [],
        history: [{ type: 'submitted', actor: reporterId, at }],
      };
      return store.update((state) => {
        state.reports.push(report);
        return { id: report.id, status: report.status, createdAt: at };
      });
    },

    listReports() {
      return store.read((state) => state.reports);
    },

    getReport(id) {
      return store.read((state) => findReport(state, id));
    },

    getReviewableReport(id, reviewerId) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      return store.read((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'in_review');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can check evidence');
        return report;
      });
    },

    startReview(id, reviewerId) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'submitted');
        if (report.reporterId === actor) fail(403, 'self_review', 'Reporter cannot review own report');
        report.status = 'in_review';
        report.classification = 'under_investigation';
        report.reviewerId = actor;
        event(report, 'review_started', actor, now());
        return report;
      });
    },

    addEvidence(id, reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'in_review');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can add evidence');
        if (report.evidence.length >= 10) fail(409, 'evidence_limit', 'Report already has 10 evidence items');
        const at = now();
        const item = evidence(input, at, actor);
        report.evidence.push(item);
        event(report, 'evidence_added', actor, at, { evidenceId: item.id });
        return item;
      });
    },

    recordOnchainObservation(id, reviewerId, observation) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'in_review');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can check evidence');
        report.observations ??= [];
        report.observations.push(structuredClone(observation));
        event(report, 'onchain_checked', actor, observation.observedAt);
        return observation;
      });
    },

    decide(id, reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      const data = object(input, 'decision');
      if (!['verified', 'rejected'].includes(data.outcome)) {
        fail(400, 'invalid_input', 'outcome must be verified or rejected');
      }
      const decisionReason = reason(data.reason);
      const advice = data.outcome === 'verified' ? string(data.advice, 'advice', 10, 500) : null;
      const classification = data.outcome === 'verified' ? data.classification : null;
      if (data.outcome === 'verified' && !['credible_threat', 'confirmed_incident'].includes(classification)) {
        fail(400, 'invalid_input', 'verified reports require credible_threat or confirmed_incident classification');
      }
      if (data.outcome === 'verified' && (!Array.isArray(data.publicEvidenceIds) || data.publicEvidenceIds.length < 1 || data.publicEvidenceIds.length > 10 ||
          data.publicEvidenceIds.some((id) => typeof id !== 'string') || new Set(data.publicEvidenceIds).size !== data.publicEvidenceIds.length)) {
        fail(400, 'invalid_input', 'verified reports require 1-10 distinct publicEvidenceIds');
      }
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'in_review');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can decide');
        if (data.outcome === 'verified' && data.publicEvidenceIds.some((evidenceId) => !report.evidence.some((item) => item.id === evidenceId))) {
          fail(400, 'invalid_input', 'publicEvidenceIds must refer to evidence in the report');
        }
        const at = now();
        report.status = data.outcome;
        report.classification = classification;
        report.publicEvidenceIds = data.outcome === 'verified' ? [...data.publicEvidenceIds] : [];
        report.decision = { outcome: data.outcome, classification, reason: decisionReason, reviewerId: actor, at, publicEvidenceIds: report.publicEvidenceIds };
        if (data.outcome === 'verified') {
          report.alertVersions.push({ at, title: report.title, advice, classification, reason: decisionReason });
        }
        event(report, data.outcome, actor, at, { reason: decisionReason });
        if (data.outcome === 'verified') enqueueNotification(state, report, 'published', at);
        return report;
      });
    },

    correct(id, reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      const data = object(input, 'correction');
      const title = string(data.title, 'title', 10, 160);
      const advice = string(data.advice, 'advice', 10, 500);
      const correctionReason = reason(data.reason);
      if (data.classification !== undefined && !['credible_threat', 'confirmed_incident'].includes(data.classification)) {
        fail(400, 'invalid_input', 'classification must be credible_threat or confirmed_incident');
      }
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'verified');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can correct');
        const at = now();
        report.classification = data.classification ?? report.classification ?? 'credible_threat';
        report.alertVersions.push({ at, title, advice, classification: report.classification, reason: correctionReason });
        event(report, 'corrected', actor, at, { reason: correctionReason });
        enqueueNotification(state, report, 'corrected', at);
        return publicAlert(report);
      });
    },

    retract(id, reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      const retractionReason = reason(object(input, 'retraction').reason);
      return store.update((state) => {
        const report = findReport(state, id);
        requireStatus(report, 'verified');
        if (report.reviewerId !== actor) fail(403, 'wrong_reviewer', 'Only assigned reviewer can retract');
        const at = now();
        report.status = 'retracted';
        report.retraction = { at, reason: retractionReason };
        event(report, 'retracted', actor, at, { reason: retractionReason });
        enqueueNotification(state, report, 'retracted', at);
        return publicAlert(report);
      });
    },

    listAlerts() {
      return store.read((state) => state.reports.filter((item) => item.status === 'verified').map(publicAlert));
    },

    listAlertHistory() {
      return store.read((state) => state.reports
        .filter((item) => ['verified', 'retracted'].includes(item.status))
        .map(publicAlert)
        .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
    },

    dashboardSummary() {
      return store.read((state) => {
        const active = state.reports.filter((item) => item.status === 'verified');
        const published = state.reports.filter((item) => ['verified', 'retracted'].includes(item.status));
        return {
          activeAlerts: active.length,
          credibleThreats: active.filter((item) => (item.classification ?? 'credible_threat') === 'credible_threat').length,
          confirmedIncidents: active.filter((item) => item.classification === 'confirmed_incident').length,
          retractedAlerts: state.reports.filter((item) => item.status === 'retracted').length,
          lastUpdatedAt: published.reduce((latest, item) => !latest || item.updatedAt > latest ? item.updatedAt : latest, null),
        };
      });
    },

    listNotificationEvents() {
      return store.read((state) => state.notificationEvents ?? []);
    },

    listContributors() {
      return store.read((state) => {
        const contributors = new Map();
        for (const report of state.reports) {
          const current = contributors.get(report.reporterId) ?? {
            reporterId: report.reporterId, reportCount: 0, verifiedCount: 0,
            rejectedCount: 0, pendingCount: 0, lastReportedAt: null,
          };
          current.reportCount++;
          if (report.status === 'verified' || report.status === 'retracted') current.verifiedCount++;
          else if (report.status === 'rejected') current.rejectedCount++;
          else current.pendingCount++;
          if (!current.lastReportedAt || report.createdAt > current.lastReportedAt) {
            current.lastReportedAt = report.createdAt;
          }
          contributors.set(report.reporterId, current);
        }
        return [...contributors.values()].sort((a, b) => b.reportCount - a.reportCount || a.reporterId.localeCompare(b.reporterId));
      });
    },

    addWatchTarget(reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      const data = object(input, 'watch target');
      if (!Number.isSafeInteger(data.chainId) || data.chainId <= 0) {
        fail(400, 'invalid_input', 'chainId must be a positive integer');
      }
      const targetAddress = address(data.address);
      const label = string(data.label, 'label', 2, 120);
      return store.update((state) => {
        state.watchlist ??= [];
        if (state.watchlist.some((item) => item.active && item.chainId === data.chainId && item.address === targetAddress)) {
          fail(409, 'duplicate_watch_target', 'Address is already on the active watchlist');
        }
        const at = now();
        const target = {
          id: randomUUID(), chainId: data.chainId, address: targetAddress, label,
          active: true, createdBy: actor, createdAt: at, updatedAt: at,
          observations: [], archived: null,
        };
        state.watchlist.push(target);
        return target;
      });
    },

    listWatchTargets() {
      return store.read((state) => state.watchlist ?? []);
    },

    getActiveWatchTarget(id) {
      return store.read((state) => {
        const target = findWatchTarget(state, id);
        if (!target.active) fail(409, 'watch_target_archived', 'Watch target is archived');
        return target;
      });
    },

    recordWatchObservation(id, reviewerId, observation) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      return store.update((state) => {
        const target = findWatchTarget(state, id);
        if (!target.active) fail(409, 'watch_target_archived', 'Watch target is archived');
        target.observations.push(structuredClone(observation));
        target.updatedAt = observation.observedAt;
        target.lastCheckedBy = actor;
        return observation;
      });
    },

    archiveWatchTarget(id, reviewerId, input) {
      const actor = string(reviewerId, 'reviewerId', 2, 80);
      const archiveReason = reason(object(input, 'archive request').reason);
      return store.update((state) => {
        const target = findWatchTarget(state, id);
        if (!target.active) fail(409, 'watch_target_archived', 'Watch target is archived');
        const at = now();
        target.active = false;
        target.archived = { by: actor, at, reason: archiveReason };
        target.updatedAt = at;
        return target;
      });
    },

    getAlert(id) {
      return store.read((state) => {
        const report = state.reports.find((item) => item.id === id);
        if (!report || !['verified', 'retracted'].includes(report.status)) {
          fail(404, 'not_found', 'Alert not found');
        }
        return publicAlert(report);
      });
    },
  };
}
