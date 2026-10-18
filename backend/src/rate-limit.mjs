// Token-bucket rate limiter for the keyless GET /v1/check endpoint.
// 60 requests/min per IP with burst 20, matching the issue #8 spec.
// Buckets live in memory: a restart resets the counters, which is acceptable
// for the demo deployment and avoids any persisted request metadata.
const CLEANUP_INTERVAL_MS = 120000;

export function createRateLimiter({ limit = 60, windowMs = 60000, burst = 20, maxBuckets = 10000 } = {}) {
  const refillPerMs = limit / windowMs;
  // Map preserves insertion order: re-inserting a used key moves it to the
  // end, so the least recently used bucket is always first — the size cap is
  // enforced in O(1) inside take() with no full-map rescans (Ollie 2026-10-18:
  // the previous per-key rescan was quadratic at 40k+ keys).
  const buckets = new Map();
  let lastCleanup = 0;
  function cleanup(atMs) {
    if (atMs - lastCleanup < CLEANUP_INTERVAL_MS) return;
    lastCleanup = atMs;
    for (const [key, bucket] of buckets) {
      if (atMs - bucket.at > windowMs) buckets.delete(key);
    }
  }
  function enforceCap() {
    while (buckets.size > maxBuckets) {
      const oldestKey = buckets.keys().next().value;
      if (oldestKey === undefined) break;
      buckets.delete(oldestKey);
    }
  }
  return {
    take(key, atMs = Date.now()) {
      cleanup(atMs);
      let bucket = buckets.get(key);
      if (bucket) {
        buckets.delete(key); // move to the end of the insertion order (LRU)
      } else {
        bucket = { tokens: burst, at: atMs };
      }
      bucket.tokens = Math.min(burst, bucket.tokens + (atMs - bucket.at) * refillPerMs);
      bucket.at = atMs;
      buckets.set(key, bucket);
      enforceCap();
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
