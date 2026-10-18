// Token-bucket rate limiter for the keyless GET /v1/check endpoint.
// 60 requests/min per IP with burst 20, matching the issue #8 spec.
// Buckets live in memory: a restart resets the counters, which is acceptable
// for the demo deployment and avoids any persisted request metadata.
const CLEANUP_INTERVAL_MS = 120000;

export function createRateLimiter({ limit = 60, windowMs = 60000, burst = 20 } = {}) {
  const refillPerMs = limit / windowMs;
  const buckets = new Map();
  let lastCleanup = 0;
  function cleanup(atMs) {
    if (atMs - lastCleanup < CLEANUP_INTERVAL_MS) return;
    lastCleanup = atMs;
    for (const [key, bucket] of buckets) {
      if (atMs - bucket.at > windowMs && bucket.tokens >= burst) buckets.delete(key);
    }
  }
  return {
    take(key, atMs = Date.now()) {
      cleanup(atMs);
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { tokens: burst, at: atMs };
        buckets.set(key, bucket);
      }
      bucket.tokens = Math.min(burst, bucket.tokens + (atMs - bucket.at) * refillPerMs);
      bucket.at = atMs;
      if (bucket.tokens >= 1) {
        bucket.tokens -= 1;
        return { ok: true, remaining: Math.floor(bucket.tokens), resetSeconds: Math.ceil((burst - bucket.tokens) / refillPerMs) };
      }
      return { ok: false, remaining: 0, resetSeconds: Math.ceil((1 - bucket.tokens) / refillPerMs) };
    },
  };
}
