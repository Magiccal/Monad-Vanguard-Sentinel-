// Token-bucket rate limiter for the keyless GET /v1/check endpoint.
// 60 requests/min per IP with burst 20, matching the issue #8 spec.
// Buckets live in memory: a restart resets the counters, which is acceptable
// for the demo deployment and avoids any persisted request metadata.
const CLEANUP_INTERVAL_MS = 120000;

export function createRateLimiter({ limit = 60, windowMs = 60000, burst = 20, maxBuckets = 10000 } = {}) {
  const refillPerMs = limit / windowMs;
  const buckets = new Map();
  let lastCleanup = 0;
  function cleanup(atMs) {
    if (atMs - lastCleanup < CLEANUP_INTERVAL_MS) return;
    lastCleanup = atMs;
    for (const [key, bucket] of buckets) {
      // Ollie 2026-10-18: refill before comparing so idle buckets actually
      // drain back to full and get evicted; also cap the map size.
      const refilled = Math.min(burst, bucket.tokens + (atMs - bucket.at) * refillPerMs);
      if (atMs - bucket.at > windowMs && refilled >= burst - 1e-9) {
        buckets.delete(key);
      } else {
        bucket.tokens = refilled;
        bucket.at = atMs;
      }
    }
    while (buckets.size > maxBuckets) {
      let oldestKey = null;
      let oldestAt = Infinity;
      for (const [key, bucket] of buckets) {
        if (bucket.at < oldestAt) { oldestAt = bucket.at; oldestKey = key; }
      }
      if (!oldestKey) break;
      buckets.delete(oldestKey);
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
        // Ollie 2026-10-18: reset/retry values are seconds, not ms.
        return {
          ok: true,
          remaining: Math.floor(bucket.tokens),
          resetSeconds: Math.max(1, Math.ceil((burst - bucket.tokens) / (refillPerMs * 1000))),
        };
      }
      return {
        ok: false,
        remaining: 0,
        resetSeconds: Math.max(1, Math.ceil((1 - bucket.tokens) / (refillPerMs * 1000))),
      };
    },
    size() { return buckets.size; },
  };
}
