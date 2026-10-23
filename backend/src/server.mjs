import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { basename, dirname, resolve } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createSentinel, DomainError } from './core.mjs';
import { createMvpService, DISCLAIMER } from './mvp.mjs';
import { Store } from './store.mjs';
import { createRpcClient, inspectTransactionEvidence, inspectWatchTarget } from './rpc.mjs';
import { createRateLimiter } from './rate-limit.mjs';
import { createQueryLog } from './query-log.mjs';

const MAX_BODY_BYTES = 64 * 1024;

function respond(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

// The check API is keyless and CORS-open so wallets, agents and web pages can
// call it. 200 responses are cacheable for 60s; 4xx/5xx keep no-store.
function checkHeaders(extra = {}) {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'x-content-type-options': 'nosniff',
    ...extra,
  };
}

function respondCheck(res, status, body, headers = {}, head = false) {
  const isError = status >= 400;
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    // 4xx/5xx stay no-store; only 2xx/304 are cacheable.
    ...(isError ? { 'cache-control': 'no-store' } : {}),
    ...headers,
  });
  res.end(head ? undefined : JSON.stringify(body));
}

// Ollie 2026-10-18 (issue #9 recheck): X-Forwarded-For must only be trusted
// when the direct socket peer is the configured trusted proxy. TRUST_PROXY
// (or the trustProxy option) is a comma-separated list of exact IPs or CIDR
// ranges (net.BlockList); '*' is intentionally NOT supported because the
// Dockerfile binds 0.0.0.0 and the container is directly reachable, so a
// wildcard would let any client spoof its way past the limit. IPv4-mapped
// IPv6 sockets (::ffff:a.b.c.d) are normalized before matching. Raw IPs are
// never persisted.
function parseTrustProxy(spec) {
  const items = (spec ?? '').split(',').map((item) => item.trim()).filter(Boolean);
  const list = new BlockList();
  for (const item of items) {
    if (item.includes('/') && isIP(item.split('/')[0])) {
      const [address, prefix] = item.split('/');
      try { list.addSubnet(address, Number(prefix)); } catch { /* ignore malformed entry */ }
    } else if (isIP(item)) {
      try { list.addAddress(item); } catch { /* ignore malformed entry */ }
    }
  }
  return list;
}

function normalizeSocketAddress(address) {
  if (typeof address !== 'string' || !address) return 'unknown';
  return address.startsWith('::ffff:') ? address.slice(7) : address;
}

function checkClientIp(req, trustList) {
  const socketAddress = normalizeSocketAddress(req.socket?.remoteAddress);
  if (trustList && trustList.check(socketAddress)) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.trim()) {
      const hops = forwarded.split(',').map((hop) => hop.trim()).filter(Boolean);
      if (hops.length) return hops[hops.length - 1];
    }
  }
  return socketAddress;
}

async function respondStatic(res, pathname, mvpPage = false) {
  const files = {
    '/': [mvpPage ? '../public/mvp.html' : '../public/index.html', 'text/html; charset=utf-8'],
    '/app.js': ['../public/app.js', 'text/javascript; charset=utf-8'],
    '/styles.css': ['../public/styles.css', 'text/css; charset=utf-8'],
    '/mvp.html': ['../public/mvp.html', 'text/html; charset=utf-8'],
    '/mvp-app.js': ['../public/mvp-app.js', 'text/javascript; charset=utf-8'],
    '/mvp.css': ['../public/mvp.css', 'text/css; charset=utf-8'],
    '/openapi.json': ['../openapi.json', 'application/json; charset=utf-8'],
    '/mvp-openapi.json': ['../mvp-openapi.json', 'application/json; charset=utf-8'],
  };
  const [path, type] = files[pathname];
  const body = await readFile(new URL(path, import.meta.url));
  res.writeHead(200, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'",
  });
  res.end(body);
}

function authorized(req, token) {
  // Accept the standard Authorization bearer header and the x-sentinel-token
  // fallback header, trying BOTH values. The fallback keeps authenticated
  // calls working behind reverse proxies that rewrite the Authorization
  // header value (observed on the hosted demo sandbox on 2026-10-08).
  const candidates = [];
  const supplied = req.headers.authorization;
  if (typeof supplied === 'string' && supplied.startsWith('Bearer ')) candidates.push(supplied.slice(7));
  const fallback = req.headers['x-sentinel-token'];
  if (typeof fallback === 'string') candidates.push(fallback);
  const expected = Buffer.from(token);
  return candidates.some((value) => {
    const actual = Buffer.from(value);
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  });
}

async function readJson(req) {
  if (!req.headers['content-type']?.toLowerCase().startsWith('application/json')) {
    throw new DomainError(415, 'unsupported_media_type', 'Content-Type must be application/json');
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > MAX_BODY_BYTES) {
      throw new DomainError(413, 'body_too_large', 'Request body exceeds 64 KiB');
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new DomainError(400, 'invalid_json', 'Request body must be valid JSON');
  }
}

export function createApiServer({ sentinel, reviewerToken, reviewerId, reviewers = null, agents = [], discordBotToken = null, mvp = null, rpc = null, trustProxy = null, agentHeaderFallback = null, agentHeaderFallbackFile = null }) {
  // Issue #8: token bucket for the keyless check API — 60 req/min per IP, burst 20.
  const checkLimiter = createRateLimiter({ limit: 60, windowMs: 60000, burst: 20 });
  // Salted 7-day abuse log; enabled only when CHECK_LOG_SALT is configured.
  const checkQueryLog = createQueryLog({ salt: process.env.CHECK_LOG_SALT || null });
  // TRUST_PROXY: comma-separated trusted proxy IPs or CIDR ranges (e.g.
  // "10.0.0.0/8, 172.16.0.5"). Empty = never trust X-Forwarded-For; buckets
  // key on the socket address. No wildcard support on purpose — the container
  // binds 0.0.0.0 and is directly reachable (Ollie 2026-10-18 recheck).
  const trustProxyList = parseTrustProxy(
    typeof trustProxy === 'string' ? trustProxy : (process.env.TRUST_PROXY ?? ''),
  );
  const configuredReviewers = reviewers ?? [{ id: reviewerId, token: reviewerToken }];
  if (![1, 3].includes(configuredReviewers.length) || configuredReviewers.some((item) =>
    typeof item.id !== 'string' || item.id.trim().length < 2 || typeof item.token !== 'string' || item.token.length < 24) ||
    new Set(configuredReviewers.map((item) => item.id)).size !== configuredReviewers.length ||
    new Set(configuredReviewers.map((item) => item.token)).size !== configuredReviewers.length) {
    throw new Error('Configure one demo reviewer or three reviewers with distinct IDs and bearer tokens of at least 24 characters');
  }
  if (discordBotToken !== null && (typeof discordBotToken !== 'string' || discordBotToken.length < 24 || configuredReviewers.some((item) => item.token === discordBotToken))) {
    throw new Error('DISCORD_BOT_TOKEN must be at least 24 characters and distinct from reviewer tokens');
  }
  // Issue #8 phase 3: registered scout agents with their own bearer tokens.
  // Empty list = agent intake disabled (routes answer 503 agents_not_configured).
  const configuredAgents = Array.isArray(agents) ? agents : [];
  if (configuredAgents.some((agent) =>
    !agent.id || typeof agent.id !== 'string' || !/^[a-z0-9_-]{2,64}$/i.test(agent.id) ||
    typeof agent.name !== 'string' || agent.name.trim().length < 2 || agent.name.length > 100 ||
    typeof agent.token !== 'string' || agent.token.length < 24) ||
    new Set(configuredAgents.map((agent) => agent.token)).size !== configuredAgents.length ||
    new Set(configuredAgents.map((agent) => agent.name.trim().toLocaleLowerCase())).size !== configuredAgents.length ||
    configuredAgents.some((agent) => configuredReviewers.some((item) => item.token === agent.token)) ||
    (discordBotToken !== null && configuredAgents.some((agent) => agent.token === discordBotToken))) {
    throw new Error('Configure agent reporters with distinct IDs (2-64 chars), case-insensitively distinct names (2-100 chars) and bearer tokens of at least 24 characters, distinct from reviewer and bot tokens');
  }
  const authenticatedReviewer = (req) => configuredReviewers.find((item) => authorized(req, item.token)) ?? null;
  // Ollie 2026-10-20 18:43 review: agent tokens are compared in constant time
  // (same as reviewer tokens) and a revoked agent (AGENTS_JSON revoked: true)
  // is rejected outright with 403.
  // PLATFORM WORKAROUND (remove on proper hosting): the hosted sandbox reverse
  // proxy rewrites the Authorization header value (observed 2026-10-08 and
  // 2026-10-20), so agent intake behind that proxy only works when the agent
  // sends the token in the x-sentinel-token fallback header instead. The
  // fallback is OFF by default and enabled only on the affected host via
  // AGENT_TOKEN_HEADER_FALLBACK=true. The hosted sandbox freezes process env
  // at first boot (observed 2026-10-20: redeploys update files but never the
  // running process env), so the affected host may alternatively drop a
  // one-line "true" file named agent-header-fallback.flag into the runtime
  // working directory; the env flag stays the primary switch and the file is
  // only read when the env var is unset. Remove both on proper hosting.
  // If a request carries a Bearer value that authenticates a known agent,
  // Bearer wins — a different agent's fallback token can never shadow the
  // Bearer identity. Otherwise the fallback header is consulted: live check
  // 2026-10-20 19:4x showed the hosted reverse proxy REPLACES the client
  // Authorization header with its own platform JWT on every public-domain
  // request, so a strict "Authorization present => ignore the fallback"
  // rule would make the workaround dead on this host. Whichever header
  // matches still goes through the same constant-time comparison, and a
  // revoked agent is rejected with 403 through either header.
  // `agentHeaderFallback` / `agentHeaderFallbackFile` override the env flag
  // and flag-file path (tests); defaults read the environment / cwd.
  const readFallbackFlagFile = (filePath) => {
    try {
      return readFileSync(filePath, 'utf8').trim().toLowerCase() === 'true' ? 'true' : 'false';
    } catch {
      return null; // no flag file: env (or the off default) decides
    }
  };
  const fallbackSetting = agentHeaderFallback
    ?? process.env.AGENT_TOKEN_HEADER_FALLBACK
    ?? readFallbackFlagFile(agentHeaderFallbackFile ?? 'agent-header-fallback.flag');
  const agentFallbackEnabled = fallbackSetting === true || fallbackSetting === 'true';
  // Compare agent tokens in constant time like reviewer tokens.
  const matchAgentToken = (token) => {
    const expected = Buffer.from(token);
    return configuredAgents.find((item) => {
      const candidate = Buffer.from(item.token);
      return candidate.length === expected.length && timingSafeEqual(candidate, expected);
    }) ?? null;
  };
  const authenticatedAgentStrict = (req) => {
    const supplied = req.headers.authorization;
    const viaBearer = typeof supplied === 'string' && supplied.startsWith('Bearer ')
      ? matchAgentToken(supplied.slice(7))
      : null;
    const agent = viaBearer
      ?? (agentFallbackEnabled && typeof req.headers['x-sentinel-token'] === 'string'
        ? matchAgentToken(req.headers['x-sentinel-token'])
        : null);
    if (agent?.revoked) throw new DomainError(403, 'agent_revoked', 'This agent token has been revoked');
    // Ollie 2026-10-20 20:41: log authentications that came through the
    // fallback header — never the token itself — so usage volume stays
    // visible and any off-host fallback usage stands out in the logs.
    if (agent && !viaBearer) {
      const route = new URL(req.url, 'http://localhost').pathname;
      console.log(`[sentinel] agent-fallback-auth agent=${agent.id} route=${req.method} ${route} at=${new Date().toISOString()}`);
    }
    return agent;
  };

  return http.createServer((req, res) => {
    (async () => {
      const pathname = new URL(req.url, 'http://localhost').pathname;
      const segments = pathname.split('/').filter(Boolean);

      if (mvp && ['/app.js', '/styles.css', '/openapi.json'].includes(pathname)) {
        throw new DomainError(410, 'legacy_demo_disabled', 'The old single-reviewer browser demo is disabled in MVP mode');
      }
      // MVP mode serves the English public incidents page at / (read-only, no login).
      const mvpPage = Boolean(mvp);
      if (req.method === 'GET' && (mvpPage
        ? ['/', '/mvp.html', '/mvp-app.js', '/mvp.css', '/mvp-openapi.json'].includes(pathname)
        : ['/', '/app.js', '/styles.css', '/openapi.json', '/mvp-openapi.json'].includes(pathname))) {
        return respondStatic(res, pathname, mvpPage);
      }

      if (req.method === 'GET' && pathname === '/health') {
        return respond(res, 200, { status: 'ok' });
      }
      // Issue #8 phase 1: keyless check API (read path). CORS-open so wallets,
      // agents and pages can call it; 200s cache for 60s; 4xx/5xx stay no-store;
      // the target is never fetched and no private data can leak (the registry
      // is built from published incidents only).
      if (mvp && segments[0] === 'v1' && segments[1] === 'check' && segments.length === 2 && ['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        const isHead = req.method === 'HEAD';
        if (req.method === 'OPTIONS') {
          res.writeHead(204, checkHeaders());
          return res.end();
        }
        const query = new URL(req.url, 'http://localhost').searchParams;
        const gate = checkLimiter.take(checkClientIp(req, trustProxyList));
        const rateHeaders = {
          'RateLimit-Limit': '60',
          'RateLimit-Remaining': String(gate.remaining),
          'RateLimit-Reset': String(Math.ceil(Date.now() / 1000) + gate.resetSeconds),
        };
        if (!gate.ok) {
          return respondCheck(res, 429, { error: 'rate_limited', message: 'Too many check requests; retry later.', disclaimer: DISCLAIMER }, checkHeaders({ ...rateHeaders, 'retry-after': String(gate.resetSeconds) }), isHead);
        }
        try {
          const body = mvp.checkTarget({ target: query.get('target'), kind: query.get('kind') });
          checkQueryLog.record(body.target.normalized, checkClientIp(req, trustProxyList));
          const etag = `W/"check-r${mvp.getCheckRegistryVersion()}"`;
          const cacheHeaders = { etag, 'cache-control': 'public, max-age=60, stale-while-revalidate=60', ...rateHeaders };
          if (typeof req.headers['if-none-match'] === 'string' && req.headers['if-none-match'].includes(etag)) {
            res.writeHead(304, checkHeaders(cacheHeaders));
            return res.end();
          }
          return respondCheck(res, 200, body, checkHeaders(cacheHeaders), isHead);
        } catch (error) {
          if (error instanceof DomainError) {
            return respondCheck(res, error.status, { error: error.code, message: error.message, disclaimer: DISCLAIMER }, checkHeaders(rateHeaders), isHead);
          }
          throw error;
        }
      }
      if (pathname === '/v1/discord/reports' && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        const body = await readJson(req);
        return respond(res, 201, await mvp.submitDiscord(body, body.discordUserId));
      }
      // Issue #8 phase 3: scout-agent report intake and reputation. Bearer
      // token identifies the registered agent; the payload never carries one.
      if (pathname === '/v1/agents/reports' && req.method === 'POST') {
        if (!mvp || !configuredAgents.length) throw new DomainError(503, 'agents_not_configured', 'Agent reporter intake is not configured');
        const agent = authenticatedAgentStrict(req);
        if (!agent) throw new DomainError(401, 'unauthorized', 'Agent reporter token required (Authorization: Bearer, or x-sentinel-token when AGENT_TOKEN_HEADER_FALLBACK=true)');
        const body = await readJson(req);
        return respond(res, 201, await mvp.submitAgentReport(body, agent.id));
      }
      if (pathname === '/v1/agents/reports' && req.method === 'GET') {
        if (!mvp || !configuredAgents.length) throw new DomainError(503, 'agents_not_configured', 'Agent reporter intake is not configured');
        const agent = authenticatedAgentStrict(req);
        if (!agent) throw new DomainError(401, 'unauthorized', 'Agent reporter token required (Authorization: Bearer, or x-sentinel-token when AGENT_TOKEN_HEADER_FALLBACK=true)');
        return respond(res, 200, mvp.listAgentReports(agent.id));
      }
      if (pathname === '/v1/agents/me' && req.method === 'GET') {
        if (!mvp || !configuredAgents.length) throw new DomainError(503, 'agents_not_configured', 'Agent reporter intake is not configured');
        const agent = authenticatedAgentStrict(req);
        if (!agent) throw new DomainError(401, 'unauthorized', 'Agent reporter token required (Authorization: Bearer, or x-sentinel-token when AGENT_TOKEN_HEADER_FALLBACK=true)');
        return respond(res, 200, mvp.agentProfile(agent.id));
      }
      if (pathname === '/v1/discord/reports/status' && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        const body = await readJson(req);
        return respond(res, 200, { reports: mvp.listDiscordReportStatus(body.discordUserId) });
      }
      if (pathname === '/v1/discord/lead-notifications' && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        const body = await readJson(req);
        return respond(res, 200, await mvp.recordLeadNotification(body));
      }
      if (pathname === '/v1/discord/reviewer-alerts' && req.method === 'GET') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        return respond(res, 200, { reports: mvp.listUnnotifiedReviewerReports() });
      }
      const reviewerNotificationMatch = pathname.match(/^\/v1\/discord\/reports\/(R-[0-9]{4,})\/reviewer-notification$/);
      if (reviewerNotificationMatch && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        return respond(res, 200, await mvp.recordReviewerReportNotification(reviewerNotificationMatch[1]));
      }
      if (segments[0] === 'v1' && segments[1] === 'mvp') {
        if (!mvp) throw new DomainError(503, 'mvp_not_configured', 'MVP workflow is not configured');
        if (segments[2] === 'incidents' && req.method === 'GET' && segments.length === 3) {
          return respond(res, 200, { incidents: mvp.listIncidents() });
        }
        if (segments[2] === 'incidents' && req.method === 'GET' && segments.length === 4) {
          return respond(res, 200, mvp.getIncident(segments[3]));
        }
        const reviewer = authenticatedReviewer(req);
        if (!reviewer) throw new DomainError(401, 'unauthorized', 'Reviewer bearer token required');
        if (segments[2] === 'ops' && segments[3] === 'scout' && req.method === 'GET') {
          // Reviewer-only visibility into the co-hosted scout (Ollie's planted-
          // test dry-run): current state (cursor, stats, filings) plus the tail
          // of the dry-run log. Paths mirror maybeAutostartScout() — the runtime
          // files live beside the relocated data file, so missing files simply
          // mean "scout not running here".
          const statePath = resolve(dirname(resolveDataFile()), 'scout-state.json');
          const logPath = resolve(dirname(resolveDataFile()), 'scout-dry-run.log');
          // The kill switch is the same file the spawned scout polls every cycle
          // (SCOUT_KILL_FILE) — creating it pauses filings on the next check
          // without a redeploy (Ollie 2026-10-23: instant stop is required during judging).
          const killPath = resolve(dirname(resolveDataFile()), 'scout-paused.flag');
          let scoutState = null;
          if (existsSync(statePath)) {
            try { scoutState = JSON.parse(readFileSync(statePath, 'utf8')); } catch { scoutState = { error: 'state file unreadable' }; }
          }
          let dryRunLog = null;
          if (existsSync(logPath)) {
            const raw = readFileSync(logPath, 'utf8');
            dryRunLog = raw.length > 20000 ? `…${raw.slice(-20000)}` : raw;
          }
          return respond(res, 200, {
            configured: existsSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'scout-autostart.flag')),
            // Ollie 2026-10-23: disclose partial coverage everywhere the scout
            // is mentioned — this endpoint is the scout's live observability surface.
            coverageNote: 'Demo hosting: partial block coverage (5.0% of produced blocks observed over a 15h window on 2026-10-23) — platform egress stalls push the scanner past the RPC receipt window (~300 blocks); every skipped range is logged in scoutState.stats.skippedRanges. Detection verified end-to-end with planted contracts; proper hosting is the post-hackathon follow-up.',
            paused: existsSync(killPath),
            // Ollie 2026-10-23: rate-capped candidates are queued, not dropped —
            // surface the queue depth here.
            queuedFilings: Array.isArray(scoutState?.rateQueue) ? scoutState.rateQueue.length : 0,
            scoutState,
            dryRunLog,
          });
        }
        // Reviewer-gated instant pause/resume for the co-hosted scout: touch or
        // remove the kill switch file the scout already checks every cycle and
        // before every filing. Effective within one poll cycle — no redeploy.
        if (segments[2] === 'ops' && segments[3] === 'scout' && segments[4] === 'pause' && req.method === 'POST' && segments.length === 5) {
          const killPath = resolve(dirname(resolveDataFile()), 'scout-paused.flag');
          writeFileSync(killPath, new Date().toISOString());
          console.log(`[sentinel] scout pause via reviewer ${reviewer.id} at=${new Date().toISOString()}`);
          return respond(res, 200, { paused: true, note: 'Kill switch created; the scout stops filing on its next check (no redeploy needed).' });
        }
        if (segments[2] === 'ops' && segments[3] === 'scout' && segments[4] === 'resume' && req.method === 'POST' && segments.length === 5) {
          const killPath = resolve(dirname(resolveDataFile()), 'scout-paused.flag');
          rmSync(killPath, { force: true });
          console.log(`[sentinel] scout resume via reviewer ${reviewer.id} at=${new Date().toISOString()}`);
          return respond(res, 200, { paused: false, note: 'Kill switch removed; the scout resumes on its next cycle.' });
        }
        if (segments[2] === 'notifications' && segments[3] === 'outbox' && req.method === 'GET' && segments.length === 4) {
          return respond(res, 200, { events: mvp.listNotificationEvents(reviewer.id) });
        }
        if (segments[2] === 'reports') {
          if (req.method === 'GET' && segments.length === 3) return respond(res, 200, { reports: mvp.listReports(reviewer.id) });
          if (req.method === 'GET' && segments.length === 4) return respond(res, 200, mvp.getReport(segments[3], reviewer.id));
          if (req.method === 'POST' && segments.length === 5) {
            const id = segments[3];
            if (segments[4] === 'triage') return respond(res, 200, await mvp.triage(id, reviewer.id, await readJson(req)));
            if (segments[4] === 'merge') return respond(res, 200, await mvp.mergeDuplicate(id, reviewer.id, await readJson(req)));
            if (segments[4] === 'dismiss') return respond(res, 200, await mvp.dismissReport(id, reviewer.id, await readJson(req)));
            if (segments[4] === 'reopen') return respond(res, 200, await mvp.reopenReport(id, reviewer.id));
            if (segments[4] === 'publication') return respond(res, 200, await mvp.proposeFromReport(id, reviewer.id, await readJson(req)));
          }
        }
        if (segments[2] === 'incidents' && req.method === 'POST' && segments.length === 5 && segments[4] === 'publication') {
          return respond(res, 200, await mvp.proposeFromIncident(segments[3], reviewer.id, await readJson(req)));
        }
        if (segments[2] === 'proposals' && segments[3] === 'pending' && req.method === 'GET' && segments.length === 4) {
          return respond(res, 200, { proposals: mvp.listPendingLeadProposals(reviewer.id) });
        }
        if (segments[2] === 'proposals') {
          if (req.method === 'GET' && segments.length === 3) return respond(res, 200, { proposals: mvp.listProposals(reviewer.id) });
          if (req.method === 'GET' && segments.length === 4) return respond(res, 200, mvp.getProposal(segments[3], reviewer.id));
          if (req.method === 'POST' && segments.length === 5 && segments[4] === 'approval') {
            return respond(res, 200, await mvp.approveProposal(segments[3], reviewer.id));
          }
          if (req.method === 'POST' && segments.length === 5 && segments[4] === 'rejection') {
            return respond(res, 200, await mvp.rejectProposal(segments[3], reviewer.id, await readJson(req)));
          }
          if (req.method === 'POST' && segments.length === 5 && segments[4] === 'evaluate') {
            return respond(res, 200, await mvp.evaluateProposal(segments[3], reviewer.id));
          }
          if (req.method === 'POST' && segments.length === 5 && segments[4] === 'cancel') {
            return respond(res, 200, await mvp.cancelProposal(segments[3], reviewer.id, await readJson(req)));
          }
        }
        throw new DomainError(404, 'not_found', 'Route not found');
      }
      if (mvp && segments[0] === 'v1') {
        throw new DomainError(410, 'legacy_demo_disabled', 'The legacy demo API is disabled when the MVP workflow is configured');
      }
      if (req.method === 'POST' && pathname === '/v1/reports') {
        return respond(res, 201, await sentinel.submit(await readJson(req)));
      }
      if (req.method === 'GET' && pathname === '/v1/alerts') {
        return respond(res, 200, { alerts: sentinel.listAlerts() });
      }
      if (req.method === 'GET' && pathname === '/v1/alerts/history') {
        return respond(res, 200, { alerts: sentinel.listAlertHistory() });
      }
      if (req.method === 'GET' && pathname === '/v1/dashboard') {
        return respond(res, 200, sentinel.dashboardSummary());
      }
      if (req.method === 'GET' && segments.length === 3 && segments[0] === 'v1' && segments[1] === 'alerts') {
        return respond(res, 200, sentinel.getAlert(segments[2]));
      }

      const reportRoute = segments[0] === 'v1' && segments[1] === 'reports' &&
        ((req.method === 'GET' && segments.length <= 3) || (req.method === 'POST' && segments.length === 4));
      const watchRoute = segments[0] === 'v1' && segments[1] === 'watchlist' &&
        ((segments.length === 2 && ['GET', 'POST'].includes(req.method)) ||
          (segments.length === 4 && req.method === 'POST'));
      const outboxRoute = req.method === 'GET' && pathname === '/v1/notifications/outbox';
      const contributorRoute = req.method === 'GET' && pathname === '/v1/contributors';
      const isReviewRoute = reportRoute || watchRoute || outboxRoute || contributorRoute;
      if (!isReviewRoute) throw new DomainError(404, 'not_found', 'Route not found');
      const reviewer = authenticatedReviewer(req);
      if (!reviewer) {
        throw new DomainError(401, 'unauthorized', 'Reviewer bearer token required');
      }
      const actingReviewerId = reviewer.id;

      if (outboxRoute) return respond(res, 200, { events: sentinel.listNotificationEvents() });
      if (contributorRoute) return respond(res, 200, { contributors: sentinel.listContributors() });
      if (watchRoute) {
        if (segments.length === 2 && req.method === 'GET') {
          return respond(res, 200, { targets: sentinel.listWatchTargets() });
        }
        if (segments.length === 2 && req.method === 'POST') {
          return respond(res, 201, await sentinel.addWatchTarget(actingReviewerId, await readJson(req)));
        }
        const id = segments[2];
        if (segments[3] === 'check') {
          if (!rpc) throw new DomainError(503, 'rpc_not_configured', 'RPC_URL is not configured');
          const target = sentinel.getActiveWatchTarget(id);
          const observation = await inspectWatchTarget(target, rpc);
          if (observation.state === 'up_to_date') return respond(res, 200, observation);
          return respond(res, 200, await sentinel.recordWatchObservation(id, actingReviewerId, observation));
        }
        if (segments[3] === 'archive') {
          return respond(res, 200, await sentinel.archiveWatchTarget(id, actingReviewerId, await readJson(req)));
        }
        throw new DomainError(404, 'not_found', 'Route not found');
      }

      if (req.method === 'GET' && segments.length === 2) {
        return respond(res, 200, { reports: sentinel.listReports() });
      }
      if (req.method === 'GET' && segments.length === 3) {
        return respond(res, 200, sentinel.getReport(segments[2]));
      }
      const id = segments[2];
      switch (segments[3]) {
        case 'review':
          return respond(res, 200, await sentinel.startReview(id, actingReviewerId));
        case 'evidence':
          return respond(res, 201, await sentinel.addEvidence(id, actingReviewerId, await readJson(req)));
        case 'check-evidence': {
          if (!rpc) throw new DomainError(503, 'rpc_not_configured', 'RPC_URL is not configured');
          const report = sentinel.getReviewableReport(id, actingReviewerId);
          const observation = await inspectTransactionEvidence(report, rpc);
          return respond(res, 200, await sentinel.recordOnchainObservation(id, actingReviewerId, observation));
        }
        case 'decision':
          return respond(res, 200, await sentinel.decide(id, actingReviewerId, await readJson(req)));
        case 'correction':
          return respond(res, 200, await sentinel.correct(id, actingReviewerId, await readJson(req)));
        case 'retraction':
          return respond(res, 200, await sentinel.retract(id, actingReviewerId, await readJson(req)));
        default:
          throw new DomainError(404, 'not_found', 'Route not found');
      }
    })().catch((error) => {
      if (res.headersSent) return res.end();
      // Ollie 2026-10-18 recheck: even unexpected errors on the check route
      // must carry CORS headers and the disclaimer.
      let isCheckRoute = false;
      try { isCheckRoute = new URL(req.url, 'http://localhost').pathname === '/v1/check'; } catch { /* keep false */ }
      if (error instanceof DomainError) {
        if (isCheckRoute) return respondCheck(res, error.status, { error: error.code, message: error.message, disclaimer: DISCLAIMER }, checkHeaders());
        return respond(res, error.status, { error: error.code, message: error.message });
      }
      console.error(error);
      if (isCheckRoute) return respondCheck(res, 500, { error: 'internal_error', message: 'Internal server error', disclaimer: DISCLAIMER }, checkHeaders());
      return respond(res, 500, { error: 'internal_error', message: 'Internal server error' });
    });
  });
}

// Ollie 2026-10-20 23:41: the hosted sandbox re-uploads the deployment
// directory on every redeploy, which overwrites reports created live in the
// sandbox. PLATFORM WORKAROUND (remove on proper hosting): when the
// configured DATA_FILE sits inside the deployment directory, the server
// keeps the live copy in a sibling sentinel-live-data/ directory outside
// it instead — migrating from the configured seed on first use, and rolling
// a small boot-time backup (5 most recent kept). Unwritable locations fall
// back to the configured file untouched.
function resolveDataFile() {
  const configured = resolve(process.env.DATA_FILE || './data/sentinel.json');
  if (!process.env.DATA_FILE) return configured; // plain local default: no relocation
  const liveDir = resolve(dirname(configured), '..', 'sentinel-live-data');
  const liveFile = resolve(liveDir, basename(configured));
  try {
    if (!existsSync(liveFile)) {
      if (!existsSync(configured)) return configured;
      mkdirSync(liveDir, { recursive: true });
      copyFileSync(configured, liveFile);
    }
    const backupsDir = resolve(liveDir, 'backups');
    mkdirSync(backupsDir, { recursive: true });
    copyFileSync(liveFile, resolve(backupsDir, `${basename(configured)}.${Date.now()}.bak`));
    for (const stale of readdirSync(backupsDir).sort().slice(0, -5)) rmSync(resolve(backupsDir, stale));
    return liveFile;
  } catch {
    return configured; // relocation impossible here: keep the configured path
  }
}

async function main() {
  const file = resolveDataFile();
  console.log(`[sentinel] data file: ${file}`);
  const store = await Store.open(file);
  const sentinel = createSentinel(store);
  const reviewers = process.env.REVIEWERS_JSON ? JSON.parse(process.env.REVIEWERS_JSON) : [{
    id: process.env.REVIEWER_ID, token: process.env.REVIEWER_TOKEN,
    discordId: process.env.REVIEWER_DISCORD_ID,
  }];
  const agents = process.env.AGENTS_JSON ? JSON.parse(process.env.AGENTS_JSON) : [];
  const mvp = process.env.DISCORD_BOT_TOKEN ? createMvpService(store, { reviewers, agents, publicBaseUrl: process.env.PUBLIC_BASE_URL || null }) : null;
  const server = createApiServer({
    sentinel,
    reviewers,
    agents,
    discordBotToken: process.env.DISCORD_BOT_TOKEN ?? null,
    mvp,
    rpc: process.env.RPC_URL ? createRpcClient(process.env.RPC_URL) : null,
  });
  const port = Number(process.env.PORT || '8787');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1-65535');
  // HOST defaults to loopback; hosted environments bind 0.0.0.0 via HOST=0.0.0.0.
  const host = process.env.HOST || '127.0.0.1';
  server.listen(port, host, () => {
    console.log(`Sentinel backend demo listening at http://${host}:${port}`);
    maybeAutostartScout(file);
  });
}

// Co-host the Envio Scout as a child process (Ollie 22:04: the scout must live
// on the always-on box, not the laptop). Triggered purely by the presence of a
// scout-autostart.flag file next to the server entry — files propagate through
// redeploys while process env is frozen, and the runtime files live in the
// sentinel-live-data directory so redeploys never wipe scout state or the
// dry-run log. A stale scout from a previous backend run is killed first so
// only one instance ever runs.
function maybeAutostartScout(dataFile) {
  const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const flagPath = resolve(rootDir, 'scout-autostart.flag');
  if (!existsSync(flagPath)) return;
  const script = resolve(rootDir, 'scout', 'envio-scout.mjs');
  if (!existsSync(script)) {
    console.log('[sentinel] scout autostart: flag present but scout/envio-scout.mjs missing — skipping');
    return;
  }
  const liveDir = dirname(dataFile); // resolveDataFile() already relocated it outside the deployment dir
  const stateFile = resolve(liveDir, 'scout-state.json');
  const dryRunLog = resolve(liveDir, 'scout-dry-run.log');
  const killFile = resolve(liveDir, 'scout-paused.flag');
  const pidFile = resolve(liveDir, 'scout.pid');
  try {
    const stale = Number(readFileSync(pidFile, 'utf8').trim());
    if (Number.isSafeInteger(stale) && stale > 1) {
      process.kill(stale, 0);
      process.kill(stale);
      console.log(`[sentinel] scout autostart: killed stale scout pid ${stale}`);
    }
  } catch { /* stale pid already gone or pidfile unreadable — nothing to kill */ }
  let agentToken = '';
  try {
    const agents = JSON.parse(process.env.AGENTS_JSON || '[]');
    agentToken = agents.find((a) => a.id === 'envio-scout')?.token ?? agents[0]?.token ?? '';
  } catch { /* no agents configured — scout runs in dry-run without filing */ }
  const child = spawn(process.execPath, [script], {
    cwd: rootDir, // scout.config.json is resolved relative to here
    env: {
      ...process.env,
      SENTINEL_TOKEN: agentToken,
      SCOUT_STATE_FILE: stateFile,
      SCOUT_DRY_RUN_LOG: dryRunLog,
      SCOUT_KILL_FILE: killFile,
    },
    stdio: 'ignore',
  });
  try { writeFileSync(pidFile, String(child.pid)); } catch { /* pidfile best-effort */ }
  child.unref();
  console.log(`[sentinel] scout autostart: pid ${child.pid} state=${stateFile} log=${dryRunLog}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
