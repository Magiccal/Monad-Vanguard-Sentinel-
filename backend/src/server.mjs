import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { createSentinel, DomainError } from './core.mjs';
import { createMvpService } from './mvp.mjs';
import { Store } from './store.mjs';
import { createRpcClient, inspectTransactionEvidence, inspectWatchTarget } from './rpc.mjs';

const MAX_BODY_BYTES = 64 * 1024;

function respond(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

async function respondStatic(res, pathname) {
  const files = {
    '/': ['../public/index.html', 'text/html; charset=utf-8'],
    '/app.js': ['../public/app.js', 'text/javascript; charset=utf-8'],
    '/styles.css': ['../public/styles.css', 'text/css; charset=utf-8'],
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
  const supplied = req.headers.authorization;
  if (typeof supplied !== 'string' || !supplied.startsWith('Bearer ')) return false;
  const actual = Buffer.from(supplied.slice(7));
  const expected = Buffer.from(token);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
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

export function createApiServer({ sentinel, reviewerToken, reviewerId, reviewers = null, discordBotToken = null, mvp = null, rpc = null }) {
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
  const authenticatedReviewer = (req) => configuredReviewers.find((item) => authorized(req, item.token)) ?? null;

  return http.createServer((req, res) => {
    (async () => {
      const pathname = new URL(req.url, 'http://localhost').pathname;
      const segments = pathname.split('/').filter(Boolean);

      if (mvp && ['/', '/app.js', '/styles.css', '/openapi.json'].includes(pathname)) {
        throw new DomainError(410, 'legacy_demo_disabled', 'The old single-reviewer browser demo is disabled in MVP mode');
      }
      if (req.method === 'GET' && ['/', '/app.js', '/styles.css', '/openapi.json', '/mvp-openapi.json'].includes(pathname)) {
        return respondStatic(res, pathname);
      }

      if (req.method === 'GET' && pathname === '/health') {
        return respond(res, 200, { status: 'ok' });
      }
      if (pathname === '/v1/discord/reports' && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        const body = await readJson(req);
        return respond(res, 201, await mvp.submitDiscord(body, body.discordUserId));
      }
      if (pathname === '/v1/discord/reports/status' && req.method === 'POST') {
        if (!mvp || !discordBotToken) throw new DomainError(503, 'mvp_not_configured', 'Trusted Discord report adapter is not configured');
        if (!authorized(req, discordBotToken)) throw new DomainError(401, 'unauthorized', 'Discord adapter bearer token required');
        const body = await readJson(req);
        return respond(res, 200, { reports: mvp.listDiscordReportStatus(body.discordUserId) });
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
            if (segments[4] === 'publication') return respond(res, 200, await mvp.proposeFromReport(id, reviewer.id, await readJson(req)));
          }
        }
        if (segments[2] === 'incidents' && req.method === 'POST' && segments.length === 5 && segments[4] === 'publication') {
          return respond(res, 200, await mvp.proposeFromIncident(segments[3], reviewer.id, await readJson(req)));
        }
        if (segments[2] === 'proposals') {
          if (req.method === 'GET' && segments.length === 4) return respond(res, 200, mvp.getProposal(segments[3], reviewer.id));
          if (req.method === 'POST' && segments.length === 5 && segments[4] === 'approval') {
            return respond(res, 200, await mvp.approveProposal(segments[3], reviewer.id));
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
      if (error instanceof DomainError) {
        return respond(res, error.status, { error: error.code, message: error.message });
      }
      console.error(error);
      return respond(res, 500, { error: 'internal_error', message: 'Internal server error' });
    });
  });
}

async function main() {
  const file = resolve(process.env.DATA_FILE || './data/sentinel.json');
  const store = await Store.open(file);
  const sentinel = createSentinel(store);
  const reviewers = process.env.REVIEWERS_JSON ? JSON.parse(process.env.REVIEWERS_JSON) : [{
    id: process.env.REVIEWER_ID, token: process.env.REVIEWER_TOKEN,
    discordId: process.env.REVIEWER_DISCORD_ID,
  }];
  const mvp = process.env.DISCORD_BOT_TOKEN ? createMvpService(store, { reviewers }) : null;
  const server = createApiServer({
    sentinel,
    reviewers,
    discordBotToken: process.env.DISCORD_BOT_TOKEN ?? null,
    mvp,
    rpc: process.env.RPC_URL ? createRpcClient(process.env.RPC_URL) : null,
  });
  const port = Number(process.env.PORT || '8787');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1-65535');
  server.listen(port, '127.0.0.1', () => {
    console.log(`Sentinel backend demo listening at http://127.0.0.1:${port}`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
