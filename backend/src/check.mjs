// Check API (read path) core: target normalization, indicator validation and
// registry matching. Phase 1 of issue #8. Public incidents are the only source;
// nothing here ever fetches the submitted target and nothing beyond the public
// incident shape feeds a response.
import { DomainError } from './core.mjs';
import { normalizeAddress, normalizeTransactionHash } from './validation.mjs';
import { isPublicSuffixDomain, isSharedHostSubdomain } from './psl-snapshots.mjs';

export const CHECK_LEVELS = ['confirmed_incident', 'credible_threat', 'under_investigation', 'informational', 'resolved', 'false_alarm'];
export const CHECK_KINDS = ['domain', 'url', 'address', 'transaction_hash'];
const CLOSED_LEVELS = new Set(['resolved', 'false_alarm']);
const LEVEL_PRIORITY = { confirmed_incident: 6, credible_threat: 5, under_investigation: 4, informational: 3, resolved: 2, false_alarm: 1 };
const SEVERITY_PRIORITY = { critical: 4, high: 3, medium: 2, low: 1 };
const MAX_TARGET_LENGTH = 2048;

function fail(status, code, message) { throw new DomainError(status, code, message); }

// ---- Normalization -------------------------------------------------------

// Domains: lowercase, IDN to punycode (WHATWG URL parser), trailing dot
// removed, scheme/port/path/query/fragment stripped, one leading "www." kept
// off. Accepts either a bare hostname or a full http(s) URL (the spec's
// indicator table allows a URL as domain input; auto-detection of a check
// target still classifies URLs as kind "url"). Returns null otherwise.
export function normalizeDomainValue(value) {
  if (typeof value !== 'string') return null;
  const input = value.trim();
  if (!input || input.length > MAX_TARGET_LENGTH || /\s/.test(input)) return null;
  let host;
  if (/^https?:\/\//i.test(input)) {
    let url;
    try { url = new URL(input); } catch { return null; }
    if (url.username || url.password) return null;
    host = url.hostname;
  } else {
    if (/[/\\?#]/.test(input) || input.includes(':')) return null;
    try { host = new URL(`http://${input}`).hostname; } catch { return null; }
  }
  if (!host) return null;
  host = host.replace(/\.$/, '');
  if (host.startsWith('www.')) host = host.slice(4);
  if (!host || /\s/.test(host)) return null;
  return host;
}

// URLs: lowercase scheme/host (parser), "www." stripped, default port removed
// (parser), fragment removed, "utm_*" params removed, path kept as-is with the
// trailing "/" removed. Credentials and non-HTTP schemes are rejected.
export function normalizeUrlValue(value) {
  if (typeof value !== 'string') return null;
  const input = value.trim();
  if (!input || input.length > MAX_TARGET_LENGTH) return null;
  let url;
  try { url = new URL(input); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
  let host = url.hostname.replace(/\.$/, '');
  if (host.startsWith('www.')) host = host.slice(4);
  if (!host) return null;
  let path = url.pathname === '/' ? '' : url.pathname;
  if (path.endsWith('/')) path = path.slice(0, -1);
  let search = '';
  const params = [...url.searchParams];
  if (params.some(([key]) => key.toLowerCase().startsWith('utm_'))) {
    const cleaned = new URLSearchParams();
    for (const [key, param] of params) {
      if (!key.toLowerCase().startsWith('utm_')) cleaned.append(key, param);
    }
    search = cleaned.size ? `?${cleaned.toString()}` : '';
  } else {
    search = url.search;
  }
  const port = url.port ? `:${url.port}` : '';
  return `${url.protocol}//${host}${port}${path}${search}`;
}

export function detectTargetKind(value) {
  const input = value.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(input)) return 'transaction_hash';
  if (/^0x[0-9a-fA-F]{40}$/.test(input)) return 'address';
  if (/^https?:\/\//i.test(input)) return 'url';
  return 'domain';
}

function hostAndPathOf(normalizedUrl) {
  // Parse with the URL API so "://" sequences and "//" inside paths cannot
  // confuse string splitting.
  try {
    const url = new URL(normalizedUrl);
    return { host: url.hostname, path: url.pathname === '/' ? '' : url.pathname };
  } catch {
    return { host: normalizedUrl, path: '' };
  }
}

// Parse and validate the query input of GET /v1/check. Throws DomainError 400
// on anything the contract rejects (missing target, >2048 chars, malformed
// hex, credentials, non-HTTP scheme, unknown or non-fitting kind).
export function normalizeCheckInput({ target, kind } = {}) {
  if (typeof target !== 'string' || !target.trim()) {
    fail(400, 'invalid_input', 'target must be a domain, http(s) URL, 0x address or 0x 32-byte transaction hash');
  }
  if (target.length > MAX_TARGET_LENGTH) {
    fail(400, 'invalid_input', `target must be at most ${MAX_TARGET_LENGTH} characters`);
  }
  const resolved = kind === undefined || kind === null ? detectTargetKind(target) : kind;
  if (!CHECK_KINDS.includes(resolved)) {
    fail(400, 'invalid_input', 'kind must be domain, url, address, or transaction_hash');
  }
  // Ollie 2026-10-18: malformed hex must be a 400, never a 200 "none" — any
  // value starting with 0x that is not exactly 40/64 hex, and any bare 40/64
  // hex without the 0x prefix, is rejected outright.
  const trimmedTarget = target.trim();
  if (/^0x/i.test(trimmedTarget) && !/^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(trimmedTarget)) {
    fail(400, 'invalid_input', '0x value must be a 40-hex address or 64-hex transaction hash');
  }
  if (/^([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(trimmedTarget)) {
    fail(400, 'invalid_input', 'hex values require the 0x prefix');
  }
  let normalized = null;
  if (resolved === 'address') normalized = normalizeAddress(target);
  else if (resolved === 'transaction_hash') normalized = normalizeTransactionHash(target);
  else if (resolved === 'url') normalized = normalizeUrlValue(target);
  else normalized = normalizeDomainValue(target);
  if (!normalized) {
    fail(400, 'invalid_input', `target does not fit kind ${resolved}; it must be a domain, http(s) URL without credentials, 0x address or 0x 32-byte transaction hash`);
  }
  return { input: target, kind: resolved, normalized };
}

// ---- Proposal-time indicator validation ----------------------------------

// Reviewer-selected indicators on a publication proposal (max 10). Returns
// null when the field is omitted (meaning "carry the previous indicators
// over") and an array when provided (an explicit empty array removes them).
// Indicators are never copied from the private report target: reviewers
// choose them explicitly, and they pass the same quorum + Lead gate.
export function validateProposalIndicators(value) {
  if (value === undefined || value === null) return null;
  if (!Array.isArray(value) || value.length > 10) {
    fail(400, 'invalid_input', 'indicators must contain at most 10 items');
  }
  const out = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      fail(400, 'invalid_input', 'each indicator must be an object with kind and value');
    }
    const kind = item.kind;
    if (!CHECK_KINDS.includes(kind)) {
      fail(400, 'invalid_input', 'indicator kind must be domain, url, address, or transaction_hash');
    }
    // Ollie 2026-10-18: reviewers may opt into subdomain matching per domain
    // indicator (same quorum + Lead gate); the default stays exact-plus-
    // subdomains for normal domains and exact-only on shared hosts.
    let matchSubdomains;
    if (item.matchSubdomains !== undefined) {
      if (kind !== 'domain') fail(400, 'invalid_input', 'matchSubdomains is only valid on domain indicators');
      if (typeof item.matchSubdomains !== 'boolean') fail(400, 'invalid_input', 'matchSubdomains must be a boolean');
      matchSubdomains = item.matchSubdomains;
    }
    let normalized = null;
    if (kind === 'domain') {
      normalized = normalizeDomainValue(item.value);
      if (!normalized || !normalized.includes('.')) {
        fail(400, 'invalid_input', 'domain indicators require a valid domain with at least two labels');
      }
      if (isPublicSuffixDomain(normalized)) {
        fail(400, 'shared_host_indicator', 'Public-suffix and shared-host domains cannot be indicators; add the full subdomain instead');
      }
    } else if (kind === 'url') {
      normalized = normalizeUrlValue(item.value);
      if (!normalized) fail(400, 'invalid_input', 'url indicators require an http(s) URL without credentials');
    } else {
      normalized = kind === 'address' ? normalizeAddress(item.value) : normalizeTransactionHash(item.value);
      if (!normalized) fail(400, 'invalid_input', `Invalid ${kind} indicator`);
    }
    out.push(matchSubdomains === undefined ? { kind, value: normalized } : { kind, value: normalized, matchSubdomains });
  }
  const seen = new Set(out.map((item) => `${item.kind}|${item.value}`));
  if (seen.size !== out.length) fail(400, 'invalid_input', 'indicators must be distinct after normalization');
  return out;
}

// ---- Registry ------------------------------------------------------------

function verifiedAtFor(incident) {
  const versions = Array.isArray(incident.timeline) ? incident.timeline : [];
  for (let index = versions.length - 1; index >= 0; index -= 1) {
    if (versions[index].level === incident.level) return versions[index].at;
  }
  return incident.updatedAt ?? null;
}

// Registry built from published incidents only. Pending proposals and
// unpublished R-#### reports never appear here. Closed incidents keep their
// indicators with active: false so a check shows the withdrawn warning.
export function buildCheckRegistry(publicIncidents) {
  const domain = [];
  const url = [];
  const exact = new Map();
  for (const incident of publicIncidents) {
    const base = {
      incidentId: incident.id,
      level: incident.level,
      severity: incident.severity,
      advice: Array.isArray(incident.advice) ? incident.advice : [],
      verifiedAt: verifiedAtFor(incident),
      active: !CLOSED_LEVELS.has(incident.level),
      priority: LEVEL_PRIORITY[incident.level] ?? 0,
      severityPriority: SEVERITY_PRIORITY[incident.severity] ?? 0,
    };
    for (const indicator of incident.indicators ?? []) {
      if (!CHECK_KINDS.includes(indicator.kind) || typeof indicator.value !== 'string') continue;
      const entry = { kind: indicator.kind, value: indicator.value, active: indicator.active ?? base.active, ...base };
      if (indicator.kind === 'domain') {
        // matchSubdomains: false forces exact matching on any domain; shared
        // hosts (parent is a PSL entry) are exact-only unless opted in.
        const exactOnly = indicator.matchSubdomains === false ||
          (isSharedHostSubdomain(indicator.value) && indicator.matchSubdomains !== true);
        domain.push({ ...entry, exactOnly });
      } else if (indicator.kind === 'url') {
        url.push(entry);
      } else {
        const bucket = exact.get(indicator.value) ?? [];
        bucket.push(entry);
        exact.set(indicator.value, bucket);
      }
    }
  }
  return { domain, url, exact };
}

function domainMatches(host, indicator) {
  if (host === indicator.value) return true;
  if (indicator.exactOnly) return false;
  return host.endsWith(`.${indicator.value}`);
}

function urlMatches(normalizedUrl, indicator) {
  const checked = hostAndPathOf(normalizedUrl);
  const pinned = hostAndPathOf(indicator.value);
  if (checked.host !== pinned.host) return false;
  const indicatorPath = pinned.path;
  if (indicatorPath === '') return true;
  return checked.path === indicatorPath || checked.path.startsWith(`${indicatorPath}/`);
}

function rank(entries) {
  return entries.sort((a, b) =>
    b.priority - a.priority ||
    b.severityPriority - a.severityPriority ||
    String(b.verifiedAt ?? '').localeCompare(String(a.verifiedAt ?? '')) ||
    String(a.incidentId).localeCompare(String(b.incidentId)));
}

// Match a normalized target against the registry. A url check also runs a
// domain check on its host; address and tx hash are exact matches. Returns the
// ranked matches (highest-priority first).
export function matchCheckTarget(registry, checked) {
  const hits = [];
  if (checked.kind === 'domain') {
    for (const indicator of registry.domain) {
      if (domainMatches(checked.normalized, indicator)) hits.push(indicator);
    }
  } else if (checked.kind === 'url') {
    for (const indicator of registry.url) {
      if (urlMatches(checked.normalized, indicator)) hits.push(indicator);
    }
    const { host } = hostAndPathOf(checked.normalized);
    for (const indicator of registry.domain) {
      if (domainMatches(host, indicator)) hits.push({ ...indicator, kind: 'domain' });
    }
  } else {
    hits.push(...(registry.exact.get(checked.normalized) ?? []));
  }
  return rank(hits).slice(0, 5);
}
