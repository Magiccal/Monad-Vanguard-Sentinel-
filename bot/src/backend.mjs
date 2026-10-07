// Thin REST client for the Sentinel MVP backend. The bot authenticates with its own
// bearer token (trusted adapter contract) and asserts reporter Discord IDs taken from
// real interactions; it never accepts a Discord user ID typed by a reporter.
import { config } from './config.mjs';

// When the process routes Discord traffic through an HTTP proxy (global dispatcher),
// backend calls to localhost must bypass it: pin an explicit direct dispatcher.
let doFetch = fetch;
if (process.env.HTTPS_PROXY || process.env.HTTP_PROXY) {
  const { fetch: undiciFetch, Agent } = await import('undici');
  const direct = new Agent();
  doFetch = (url, init) => undiciFetch(url, { ...init, dispatcher: direct });
}

async function call(path, { method = 'GET', token, body } = {}) {
  const response = await doFetch(`${config.backendBaseUrl}${path}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload?.message ?? `Backend call ${method} ${path} failed with HTTP ${response.status}`);
    error.code = payload?.code ?? 'backend_error';
    error.status = response.status;
    throw error;
  }
  return payload;
}

export const backend = {
  // Bot-authenticated reporter surfaces.
  submitReport(discordUserId, input) {
    return call('/v1/discord/reports', { method: 'POST', token: config.botBackendToken, body: { discordUserId, ...input } });
  },
  reportStatus(discordUserId) {
    return call('/v1/discord/reports/status', { method: 'POST', token: config.botBackendToken, body: { discordUserId } });
  },

  // Public, reviewer-approved incidents (also served to the no-login web page).
  listIncidents() {
    return call('/v1/mvp/incidents');
  },

  // Reviewer-only feeds used by the bot's delivery loops.
  notificationOutbox() {
    return call('/v1/mvp/notifications/outbox', { token: config.reviewerToken });
  },
  pendingLeadProposals() {
    return call('/v1/mvp/proposals/pending', { token: config.reviewerToken });
  },

  // The one-hour Lead fallback clock starts only on a confirmed delivery.
  confirmLeadNotification(proposalId, delivered) {
    return call('/v1/discord/lead-notifications', { method: 'POST', token: config.botBackendToken, body: { proposalId, delivered } });
  },
};
