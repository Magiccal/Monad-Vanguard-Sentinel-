// In-memory abuse log for the keyless check API (issue #8 section 5): only a
// salted hash of the normalized target and of the client IP is kept, never the
// raw values, and entries expire after 7 days. The salt is a secret
// environment variable (CHECK_LOG_SALT), never committed, rotated every 30
// days — safe because old entries expire before the rotation matters. Nothing
// here touches disk: a restart clears the log by design.
import { createHash } from 'node:crypto';

const TTL_MS = 7 * 24 * 60 * 60 * 1000;

export function createQueryLog({ salt = null, maxEntries = 10000 } = {}) {
  const entries = [];
  const digest = (value) => createHash('sha256').update(`${salt}:${value}`).digest('hex').slice(0, 32);
  return {
    record(normalizedTarget, clientIp, atMs = Date.now()) {
      if (!salt) return; // logging disabled until a secret salt is configured
      entries.push({ at: atMs, target: digest(normalizedTarget), ip: digest(clientIp) });
      while (entries.length > 0 && (entries[0].at < atMs - TTL_MS || entries.length > maxEntries)) {
        entries.shift();
      }
    },
    size() { return entries.length; },
  };
}
