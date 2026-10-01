import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';
import { createSentinel, DomainError } from './core.mjs';
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

export function createApiServer({ sentinel, reviewerToken, reviewerId, rpc = null }) {
  if (typeof reviewerToken !== 'string' || reviewerToken.length < 24) {
    throw new Error('REVIEWER_TOKEN must be at least 24 characters');
  }
  if (typeof reviewerId !== 'string' || reviewerId.trim().length < 2) {
    throw new Error('REVIEWER_ID is required');
  }

  return http.createServer((req, res) => {
    (async () => {
      const pathname = new URL(req.url, 'http://localhost').pathname;
      const segments = pathname.split('/').filter(Boolean);

      if (req.method === 'GET' && ['/', '/app.js', '/styles.css', '/openapi.json'].includes(pathname)) {
        return respondStatic(res, pathname);
      }

      if (req.method === 'GET' && pathname === '/health') {
        return respond(res, 200, { status: 'ok' });
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
      if (!authorized(req, reviewerToken)) {
        throw new DomainError(401, 'unauthorized', 'Reviewer bearer token required');
      }

      if (outboxRoute) return respond(res, 200, { events: sentinel.listNotificationEvents() });
      if (contributorRoute) return respond(res, 200, { contributors: sentinel.listContributors() });
      if (watchRoute) {
        if (segments.length === 2 && req.method === 'GET') {
          return respond(res, 200, { targets: sentinel.listWatchTargets() });
        }
        if (segments.length === 2 && req.method === 'POST') {
          return respond(res, 201, await sentinel.addWatchTarget(reviewerId, await readJson(req)));
        }
        const id = segments[2];
        if (segments[3] === 'check') {
          if (!rpc) throw new DomainError(503, 'rpc_not_configured', 'RPC_URL is not configured');
          const target = sentinel.getActiveWatchTarget(id);
          const observation = await inspectWatchTarget(target, rpc);
          return respond(res, 200, await sentinel.recordWatchObservation(id, reviewerId, observation));
        }
        if (segments[3] === 'archive') {
          return respond(res, 200, await sentinel.archiveWatchTarget(id, reviewerId, await readJson(req)));
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
          return respond(res, 200, await sentinel.startReview(id, reviewerId));
        case 'evidence':
          return respond(res, 201, await sentinel.addEvidence(id, reviewerId, await readJson(req)));
        case 'check-evidence': {
          if (!rpc) throw new DomainError(503, 'rpc_not_configured', 'RPC_URL is not configured');
          const report = sentinel.getReviewableReport(id, reviewerId);
          const observation = await inspectTransactionEvidence(report, rpc);
          return respond(res, 200, await sentinel.recordOnchainObservation(id, reviewerId, observation));
        }
        case 'decision':
          return respond(res, 200, await sentinel.decide(id, reviewerId, await readJson(req)));
        case 'correction':
          return respond(res, 200, await sentinel.correct(id, reviewerId, await readJson(req)));
        case 'retraction':
          return respond(res, 200, await sentinel.retract(id, reviewerId, await readJson(req)));
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
  const server = createApiServer({
    sentinel,
    reviewerToken: process.env.REVIEWER_TOKEN,
    reviewerId: process.env.REVIEWER_ID,
    rpc: process.env.RPC_URL ? createRpcClient(process.env.RPC_URL) : null,
  });
  const port = Number(process.env.PORT || '8787');
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1-65535');
  server.listen(port, '127.0.0.1', () => {
    console.log(`Sentinel prototype listening at http://127.0.0.1:${port}`);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
