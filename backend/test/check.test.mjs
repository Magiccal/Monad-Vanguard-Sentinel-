import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { readFile } from 'node:fs/promises';
import { createMvpService } from '../src/mvp.mjs';
import { createSentinel } from '../src/core.mjs';
import { createApiServer } from '../src/server.mjs';
import { Store } from '../src/store.mjs';
import { createRateLimiter } from '../src/rate-limit.mjs';
import { normalizeDomainValue, normalizeUrlValue, normalizeCheckInput, matchCheckTarget, buildCheckRegistry } from '../src/check.mjs';

const reviewer = { id: 'demo-reviewer', discordId: '100000000000000001', token: 'demo-reviewer-test-secret-token-123456' };
const DISCLAIMER = 'Independent community project · Not affiliated with Monad Foundation · Not financial advice';
const NONE_ADVICE = 'No published Sentinel incident matches this target. This is not a safety guarantee; verify through official channels.';

async function buildDemo({ indicator = { kind: 'domain', value: 'velunor-claim.xyz' } } = {}) {
  const store = await Store.open();
  let step = 0;
  const mvp = createMvpService(store, {
    now: () => new Date(Date.parse('2026-10-12T14:00:00.000Z') + (step++) * 60000).toISOString(),
    reviewers: [reviewer],
    publicBaseUrl: 'https://sentinel-security-demo.app.workbuddy.host',
  });
  await mvp.submitDiscord({
    description: 'DEMO CONTENT. A fake claim site for the fictional Velunor project is asking users to connect their wallets.',
    incidentType: 'phishing',
    targets: [{ kind: 'url', value: 'https://velunor-claim.xyz' }],
    evidence: [{ kind: 'official_statement', reference: 'https://velunor.example/announcements/fake-claim-warning' }],
  }, '200000000000000002');
  const report = mvp.listReports(reviewer.id)[0];
  await mvp.proposeFromReport(report.id, reviewer.id, {
    level: 'credible_threat', severity: 'high',
    title: 'Fake Velunor ($VLN) claim site',
    summary: 'DEMO CONTENT. A fake Velunor claim site is asking users to connect their wallets to steal approvals.',
    verificationNote: 'Reporter screenshots and the fake claim page were reviewed before publication.',
    advice: ['Do not connect your wallet to velunor-claim[.]xyz.', 'If you connected, revoke approvals now.'],
    reason: 'Publishing as a credible threat because the fake claim page actively requests wallet connections.',
    publicEvidenceIds: report.evidence.map((item) => item.id),
    ...(indicator ? { indicators: [indicator] } : {}),
  });
  return { store, mvp };
}

function invoke(server, method, url, { headers = {}, socket = null } = {}) {
  return new Promise((resolve) => {
    const req = Readable.from([]);
    Object.assign(req, { method, url, headers, socket: socket ?? { remoteAddress: null } });
    const res = {
      headersSent: false,
      writeHead(status, resHeaders) {
        this.status = status;
        this.headers = { ...(this.headers ?? {}), ...(resHeaders ?? {}) };
        this.headersSent = true;
      },
      end(payload) {
        this.headers ??= {};
        const raw = payload === undefined || payload === null ? '' : payload.toString();
        let body = raw;
        if (raw) { try { body = JSON.parse(raw); } catch { /* raw text (304 has no body) */ } }
        resolve({ status: this.status, headers: this.headers, body });
      },
    };
    server.emit('request', req, res);
  });
}

test('domain and url normalization follows the issue #8 table', () => {
  assert.equal(normalizeDomainValue('WWW.Velunor-Claim.xyz.'), 'velunor-claim.xyz');
  assert.equal(normalizeDomainValue('https://velunor-claim.xyz/claim?a=1'), 'velunor-claim.xyz');
  assert.equal(normalizeDomainValue('Bücher.example'), 'xn--bcher-kva.example');
  assert.equal(normalizeDomainValue('not a domain'), null);
  assert.equal(normalizeDomainValue('javascript:alert(1)'), null);
  assert.equal(normalizeUrlValue('http://Example.com:80/Claim/?utm_source=x&utm_medium=y&keep=1#top'), 'http://example.com/Claim?keep=1');
  assert.equal(normalizeUrlValue('https://www.APP.Velunor-Claim.xyz/claim/'), 'https://app.velunor-claim.xyz/claim');
  assert.equal(normalizeUrlValue('ftp://example.com/x'), null);
  assert.equal(normalizeUrlValue('https://user:pass@example.com/x'), null);
  const input = normalizeCheckInput({ target: `0x${'A'.repeat(40)}` });
  assert.equal(input.kind, 'address');
  assert.equal(input.normalized, `0x${'a'.repeat(40)}`);
  assert.equal(normalizeCheckInput({ target: `0x${'b'.repeat(64)}` }).kind, 'transaction_hash');
  assert.equal(normalizeCheckInput({ target: 'https://a.example/x' }).kind, 'url');
  assert.equal(normalizeCheckInput({ target: 'velunor-claim.xyz' }).kind, 'domain');
});

test('url prefix matching respects the slash boundary and ignores the query', () => {
  const registry = buildCheckRegistry([{
    id: 'SEN-0001', level: 'credible_threat', severity: 'high', updatedAt: '2026-10-12T14:05:00.000Z',
    advice: ['Do not interact.'], indicators: [{ kind: 'url', value: 'https://evil.example/login', active: true }],
    timeline: [{ at: '2026-10-12T14:05:00.000Z', level: 'credible_threat' }],
  }]);
  assert.equal(matchCheckTarget(registry, { kind: 'url', normalized: 'https://evil.example/login/extra?q=1' }).length, 1);
  assert.equal(matchCheckTarget(registry, { kind: 'url', normalized: 'https://evil.example/login-reset' }).length, 0);
  assert.equal(matchCheckTarget(registry, { kind: 'url', normalized: 'https://other.example/login' }).length, 0);
});

test('check API returns the published warning for the Velunor domain in all accepted forms', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  for (const target of ['velunor-claim.xyz', 'WWW.VELUNOR-CLAIM.XYZ.', 'https://app.velunor-claim.xyz/x?y=1']) {
    const res = await invoke(server, 'GET', `/v1/check?target=${encodeURIComponent(target)}`);
    assert.equal(res.status, 200);
    assert.equal(res.body.matched, true, target);
    assert.equal(res.body.level, 'credible_threat');
    assert.equal(res.body.severity, 'high');
    assert.equal(res.body.incidentId, 'SEN-0001');
    assert.equal(res.body.incidentUrl, 'https://sentinel-security-demo.app.workbuddy.host/mvp.html#SEN-0001');
    assert.deepEqual(res.body.matchedIndicator, { kind: 'domain', value: 'velunor-claim.xyz', active: true });
    assert.equal(res.body.disclaimer, DISCLAIMER);
    assert.ok(Array.isArray(res.body.advice) && res.body.advice.length >= 1);
  }
});

test('unrelated hosts, bare TLDs, and unpublished report targets return level none', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  for (const target of ['notvelunor-claim.xyz', 'xyz', 'https://safe.example/claim']) {
    const res = await invoke(server, 'GET', `/v1/check?target=${encodeURIComponent(target)}`);
    assert.equal(res.status, 200, target);
    assert.equal(res.body.matched, false, target);
    assert.equal(res.body.level, 'none', target);
    assert.deepEqual(res.body.advice, [NONE_ADVICE]);
    assert.equal(res.body.incidentId, null);
    assert.equal(res.body.disclaimer, DISCLAIMER);
  }
  // Mixed-case and lowercase address forms return the same result (none here).
  const upper = await invoke(server, 'GET', `/v1/check?target=0x${'A'.repeat(40)}`);
  const lower = await invoke(server, 'GET', `/v1/check?target=0x${'a'.repeat(40)}`);
  assert.deepEqual(upper.body.matches, lower.body.matches);
  assert.equal(upper.body.level, 'none');
});

test('invalid check input returns 400 invalid_input with the disclaimer', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const cases = [
    '/v1/check',
    `/v1/check?target=${'x'.repeat(2049)}`,
    `/v1/check?target=0x${'a'.repeat(39)}`,
    `/v1/check?target=0x${'a'.repeat(41)}`,
    `/v1/check?target=0x${'a'.repeat(63)}`,
    '/v1/check?target=javascript:alert(1)',
    `/v1/check?target=${encodeURIComponent('https://user:pass@example.com/x')}`,
    '/v1/check?target=example.com&kind=hologram',
    `/v1/check?target=0x${'a'.repeat(64)}&kind=address`,
  ];
  for (const url of cases) {
    const res = await invoke(server, 'GET', url);
    assert.equal(res.status, 400, url);
    assert.equal(res.body.error, 'invalid_input', url);
    assert.equal(res.body.disclaimer, DISCLAIMER, url);
  }
});

test('closed incidents keep indicators inactive and return the closure advice', async () => {
  const { store, mvp } = await buildDemo();
  await mvp.proposeFromIncident('SEN-0001', reviewer.id, {
    level: 'false_alarm', severity: 'high',
    title: 'Fake Velunor ($VLN) claim site',
    summary: 'DEMO CONTENT. The reported claim site was confirmed fictional demo content and no real threat exists.',
    verificationNote: 'Closure reviewed against the fictional demo evidence.',
    advice: ['No action needed.'],
    reason: 'Closing as a false alarm because the site was part of a fictional demonstration.',
  });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.equal(res.status, 200);
  assert.equal(res.body.matched, true);
  assert.equal(res.body.level, 'false_alarm');
  assert.deepEqual(res.body.advice, ['No action needed.']);
  assert.deepEqual(res.body.matchedIndicator, { kind: 'domain', value: 'velunor-claim.xyz', active: false });
});

test('a correction that omits indicators carries them over; an explicit [] removes them', async () => {
  const { store, mvp } = await buildDemo();
  // Omitted field: the indicators (including matchSubdomains) carry over, so
  // an active threat never silently loses its check warning.
  await mvp.proposeFromIncident('SEN-0001', reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Fake Velunor ($VLN) claim site',
    summary: 'DEMO CONTENT. The claim site investigation continues and the warning stays active.',
    verificationNote: 'Correction reviewed by the demo reviewer without changing indicators.',
    advice: ['Wait for reviewer guidance before interacting with this fictional site.'],
    reason: 'Downgrading the level while keeping the published check indicators unchanged.',
  });
  let server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const carried = await invoke(server, 'GET', '/v1/check?target=app.velunor-claim.xyz');
  assert.equal(carried.body.matched, true);
  assert.equal(carried.body.level, 'under_investigation');
  assert.deepEqual(carried.body.matchedIndicator, { kind: 'domain', value: 'velunor-claim.xyz', active: true });
  // Explicit empty array: the reviewer deliberately removes the indicators.
  await mvp.proposeFromIncident('SEN-0001', reviewer.id, {
    level: 'informational', severity: null,
    title: 'Fictional Velunor demo downgraded',
    summary: 'DEMO CONTENT. The fictional Velunor demonstration incident is downgraded and its indicator was removed.',
    verificationNote: 'Correction reviewed by the demo reviewer.',
    advice: ['No action is required for this fictional demo.'],
    reason: 'Removing the indicator because the demonstration incident no longer needs a check warning.',
    indicators: [],
  });
  server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const removed = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.equal(removed.body.matched, false);
  assert.equal(removed.body.level, 'none');
});

test('a closed correction with an explicit empty indicator list removes them', async () => {
  const { store, mvp } = await buildDemo();
  await mvp.proposeFromIncident('SEN-0001', reviewer.id, {
    level: 'false_alarm', severity: 'high',
    title: 'Fake Velunor ($VLN) claim site',
    summary: 'DEMO CONTENT. The reported claim site was confirmed fictional demo content and no real threat exists.',
    verificationNote: 'Closure reviewed against the fictional demo evidence.',
    advice: ['No action needed.'],
    reason: 'Closing as a false alarm and deliberately removing the check indicator.',
    indicators: [],
  });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.equal(res.body.matched, false);
  assert.equal(res.body.level, 'none');
});

test('matchSubdomains: false pins an indicator to exact matching', async () => {
  const { store, mvp } = await buildDemo({ indicator: { kind: 'domain', value: 'velunor-claim.xyz', matchSubdomains: false } });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const exact = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.equal(exact.body.matched, true);
  const sub = await invoke(server, 'GET', '/v1/check?target=app.velunor-claim.xyz');
  assert.equal(sub.body.matched, false);
});

test('shared-host and public-suffix domain indicators are rejected at proposal time', async () => {
  const { store, mvp } = await buildDemo({ indicator: null });
  await mvp.submitDiscord({
    description: 'DEMO CONTENT. A second report listing an invalid shared-host indicator for rejection checks.',
    incidentType: 'phishing', targets: [{ kind: 'url', value: 'https://evil.vercel.app/claim' }],
  }, '200000000000000003');
  const report = mvp.listReports(reviewer.id)[1];
  for (const value of ['vercel.app', 'github.io', 'appspot.com', 'eu.org', 'co.uk', 'xyz']) {
    await assert.rejects(() => mvp.proposeFromReport(report.id, reviewer.id, {
      level: 'under_investigation', severity: 'medium',
      title: 'Shared-host listing must be rejected', summary: 'DEMO CONTENT. This proposal must be rejected because of its invalid indicator value.',
      verificationNote: 'The indicator is invalid, so the proposal must not be created.',
      advice: ['Do not interact with this fictional target.'],
      reason: 'Attempting to list a shared-host or suffix root must fail at proposal time.',
      indicators: [{ kind: 'domain', value }],
    }), (error) => ['shared_host_indicator', 'invalid_input'].includes(error.code), value);
  }
  // A full subdomain of a shared host is allowed (demo mode auto-publishes it).
  const ok = await mvp.proposeFromReport(report.id, reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Shared-host subdomain listing', summary: 'DEMO CONTENT. This proposal is allowed because it lists a full shared-host subdomain.',
    verificationNote: 'The full subdomain is specific enough for a check warning.',
    advice: ['Do not interact with this fictional target.'],
    reason: 'Listing a full subdomain of a shared host is the documented workaround.',
    indicators: [{ kind: 'domain', value: 'evil.vercel.app' }],
  });
  assert.ok(['pending', 'published'].includes(ok.status));
  // It matches exactly only: sibling subdomains on the platform stay clean.
  const registry = buildCheckRegistry(mvp.listIncidents());
  assert.equal(matchCheckTarget(registry, { kind: 'domain', normalized: 'other.vercel.app' }).length, 0);
  assert.equal(matchCheckTarget(registry, { kind: 'domain', normalized: 'evil.vercel.app' }).length, 1);
});

test('highest-priority active match wins and matches[] carries every entry', async () => {
  const { store, mvp } = await buildDemo();
  await mvp.submitDiscord({
    description: 'DEMO CONTENT. A second report about the same fictional Velunor claim site for priority checks.',
    incidentType: 'phishing', targets: [{ kind: 'url', value: 'https://velunor-claim.xyz/second' }],
  }, '200000000000000003');
  const second = mvp.listReports(reviewer.id)[1];
  await mvp.proposeFromReport(second.id, reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Velunor claim site under review', summary: 'DEMO CONTENT. A second, lower-priority look at the same fictional Velunor claim site.',
    verificationNote: 'Lower-priority publication used to exercise the match priority order.',
    advice: ['Wait for reviewer guidance before interacting with this fictional site.'],
    reason: 'Publishing a lower-priority incident so the check API returns the highest match first.',
    indicators: [{ kind: 'domain', value: 'velunor-claim.xyz' }],
  });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.equal(res.body.level, 'credible_threat');
  assert.equal(res.body.incidentId, 'SEN-0001');
  assert.ok(res.body.matches.length >= 2);
});

test('rate limiting, caching, CORS, and OPTIONS preflight behave per the spec', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const headers = { 'x-forwarded-for': '203.0.113.10' };
  const first = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers });
  assert.equal(first.headers['access-control-allow-origin'], '*');
  assert.equal(first.headers['cache-control'], 'public, max-age=60, stale-while-revalidate=60');
  assert.ok(first.headers.etag.startsWith('W/'));
  const cached = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { ...headers, 'if-none-match': first.headers.etag } });
  assert.equal(cached.status, 304);
  const preflight = await invoke(server, 'OPTIONS', '/v1/check?target=velunor-claim.xyz', { headers });
  assert.equal(preflight.status, 204);
  assert.equal(preflight.headers['access-control-allow-methods'], 'GET, OPTIONS');
  // A different X-Forwarded-For value keeps its own bucket.
  const other = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': '203.0.113.11' } });
  assert.equal(other.status, 200);
  // Burst 20: a rapid request series from the same IP hits the limiter with 429.
  let limited = null;
  for (let index = 0; index < 30; index += 1) {
    const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers });
    if (res.status === 429) { limited = res; break; }
  }
  assert.ok(limited, 'expected a 429 within the burst window');
  assert.equal(limited.body.error, 'rate_limited');
  assert.equal(limited.body.disclaimer, DISCLAIMER);
  const retry = Number(limited.headers['retry-after']);
  assert.ok(Number.isInteger(retry) && retry >= 1 && retry <= 120, `retry-after must be whole seconds, got ${limited.headers['retry-after']}`);
  const reset = Number(limited.headers['RateLimit-Reset']);
  const nowSeconds = Math.ceil(Date.now() / 1000);
  assert.ok(Number.isInteger(reset) && reset >= nowSeconds && reset <= nowSeconds + 120, `RateLimit-Reset must be epoch seconds within the window, got ${limited.headers['RateLimit-Reset']}`);
  assert.ok(limited.headers['RateLimit-Limit']);
  // 429 stays no-store.
  assert.equal(limited.headers['cache-control'], 'no-store');
});

test('X-Forwarded-For is only honored from a trusted proxy socket', async () => {
  const { store, mvp } = await buildDemo();
  // TRUST_PROXY = 10.0.0.1: buckets key on the last XFF hop only when the
  // socket peer is the trusted proxy.
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer], trustProxy: '10.0.0.1' });
  const viaProxy = { socket: { remoteAddress: '10.0.0.1' } };
  const direct = { socket: { remoteAddress: '198.51.100.7' } };
  const honest = '9.9.9.9';
  const spoofVariants = [`1.2.3.4, ${honest}`, `5.6.7.8, ${honest}`, `a.a.a.a, b.b.b.b, ${honest}`, honest];
  let limited = 0;
  for (let index = 0; index < 25; index += 1) {
    const forwarded = spoofVariants[index % spoofVariants.length];
    const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': forwarded }, ...viaProxy });
    if (res.status === 429) limited += 1;
  }
  assert.ok(limited > 0, 'spoofed first hops behind the trusted proxy share one bucket');
  // A direct (untrusted) socket keeps its own bucket: spoofed XFF cannot push
  // another user into 429, and ignoring the header entirely protects them.
  for (let index = 0; index < 19; index += 1) {
    const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': `10.0.0.${index + 1}` }, ...direct });
    assert.equal(res.status, 200, 'untrusted socket must not be rate-limited via spoofed XFF');
  }
});

test('idle rate-limit buckets are evicted after the window and the map is capped', () => {
  const limiter = createRateLimiter({ limit: 60, windowMs: 60000, burst: 20, maxBuckets: 3 });
  assert.equal(limiter.take('a', 0).ok, true);
  assert.equal(limiter.size(), 1);
  // Advancing past the cleanup interval refills then evicts the idle bucket.
  assert.equal(limiter.take('b', 121000).ok, true);
  assert.equal(limiter.size(), 1, 'idle bucket must be evicted');
  // Size cap: the next cleanup pass evicts idle buckets down to the cap.
  limiter.take('c', 121500);
  limiter.take('d', 122000);
  limiter.take('e', 122500);
  limiter.take('f', 243000); // past the cleanup interval → sweep runs
  assert.ok(limiter.size() <= 3, 'bucket map must stay capped');
});

test('check responses contain no field absent from the public incident', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const incident = mvp.listIncidents()[0];
  const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz');
  assert.deepEqual(res.body.advice, incident.advice);
  assert.deepEqual(res.body.matchedIndicator, {
    kind: incident.indicators[0].kind, value: incident.indicators[0].value, active: incident.indicators[0].active,
  });
  assert.equal(res.body.verifiedAt, incident.updatedAt);
});

test('the bundled example matches the live response shape', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  const example = JSON.parse(await readFile(new URL('../examples/check-match-response.json', import.meta.url), 'utf8'));
  const res = await invoke(server, 'GET', `/v1/check?target=${encodeURIComponent(example.target.input)}`);
  assert.deepEqual(Object.keys(res.body).sort(), Object.keys(example).sort());
  assert.equal(res.body.incidentId, example.incidentId);
  assert.equal(res.body.level, example.level);
});

test('0x-prefixed domains stay valid checks; only all-hex 0x values are hex', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  for (const target of ['0x.org', '0xgallery.xyz', '0xzzzz-not-hex']) {
    const res = await invoke(server, 'GET', `/v1/check?target=${encodeURIComponent(target)}`);
    assert.equal(res.status, 200, target);
    assert.equal(res.body.level, 'none', target);
    assert.equal(res.body.target.kind, 'domain', target);
  }
  // All-hex after 0x with the wrong length is still a 400.
  const bad = await invoke(server, 'GET', `/v1/check?target=0x${'a'.repeat(63)}`);
  assert.equal(bad.status, 400);
  const missing0x = await invoke(server, 'GET', `/v1/check?target=${'a'.repeat(40)}`);
  assert.equal(missing0x.status, 400);
});

test('TRUST_PROXY supports CIDR ranges and IPv4-mapped IPv6 sockets', async () => {
  const { store, mvp } = await buildDemo();
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer], trustProxy: '10.0.0.0/8, 172.16.0.5' });
  const cidrSocket = { socket: { remoteAddress: '10.1.2.3' } };
  const mappedSocket = { socket: { remoteAddress: '::ffff:172.16.0.5' } };
  const outsideSocket = { socket: { remoteAddress: '192.0.2.9' } };
  // Trusted via CIDR: the last XFF hop keys the bucket.
  const viaCidr = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': '9.9.9.9' }, ...cidrSocket });
  assert.equal(viaCidr.status, 200);
  // Same last hop via the IPv4-mapped trusted socket → same bucket.
  const viaMapped = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': '8.8.8.8, 9.9.9.9' }, ...mappedSocket });
  assert.equal(viaMapped.status, 200);
  // Sockets outside TRUST_PROXY ignore XFF and key on their own address.
  for (let index = 0; index < 20; index += 1) {
    const res = await invoke(server, 'GET', '/v1/check?target=velunor-claim.xyz', { headers: { 'x-forwarded-for': `10.9.9.${index}` }, ...outsideSocket });
    assert.equal(res.status, 200, 'untrusted socket must not be limited via spoofed XFF');
  }
});

test('ICANN-suffix parents keep subdomain matching (only PRIVATE parents are shared hosts)', async () => {
  const { store, mvp } = await buildDemo({ indicator: { kind: 'domain', value: 'evil-bank.co.uk' } });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers: [reviewer] });
  // evil-bank.co.uk sits under the ICANN suffix co.uk: it is a normal
  // registrable domain, so its subdomains match.
  const res = await invoke(server, 'GET', '/v1/check?target=login.evil-bank.co.uk');
  assert.equal(res.body.matched, true);
  assert.equal(res.body.incidentId, 'SEN-0001');
  // The shared-host exact-only rule still applies to PRIVATE parents.
  const registry = buildCheckRegistry(mvp.listIncidents());
  assert.equal(matchCheckTarget(registry, { kind: 'domain', normalized: 'login.evil-bank.co.uk' }).length, 1);
});

test('matchSubdomains is an opt-in per domain indicator with a safe default', async () => {
  const { store, mvp } = await buildDemo({ indicator: null });
  await mvp.submitDiscord({
    description: 'DEMO CONTENT. A report listing a shared-host subdomain indicator with subdomain matching enabled.',
    incidentType: 'phishing', targets: [{ kind: 'url', value: 'https://evil.vercel.app/claim' }],
  }, '200000000000000004');
  const report = mvp.listReports(reviewer.id)[1];
  // matchSubdomains is domain-only and must be a boolean.
  await assert.rejects(() => mvp.proposeFromReport(report.id, reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Bad matchSubdomains on url', summary: 'DEMO CONTENT. This proposal must be rejected because matchSubdomains is not valid on url indicators.',
    verificationNote: 'The indicator options are invalid, so the proposal must not be created.',
    advice: ['Do not interact with this fictional target.'],
    reason: 'matchSubdomains only applies to domain indicators per the check API spec.',
    indicators: [{ kind: 'url', value: 'https://evil.vercel.app/x', matchSubdomains: true }],
  }), (error) => error.code === 'invalid_input');
  await assert.rejects(() => mvp.proposeFromReport(report.id, reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Bad matchSubdomains type', summary: 'DEMO CONTENT. This proposal must be rejected because matchSubdomains is not a boolean.',
    verificationNote: 'The indicator options are invalid, so the proposal must not be created.',
    advice: ['Do not interact with this fictional target.'],
    reason: 'matchSubdomains must be a boolean when provided on a domain indicator.',
    indicators: [{ kind: 'domain', value: 'evil.vercel.app', matchSubdomains: 'yes' }],
  }), (error) => error.code === 'invalid_input');
  // Opt-in: the published shared-host indicator now covers its subdomains.
  await mvp.proposeFromReport(report.id, reviewer.id, {
    level: 'under_investigation', severity: 'medium',
    title: 'Shared-host subdomain opt-in', summary: 'DEMO CONTENT. This proposal opts into subdomain matching for a shared-host subdomain.',
    verificationNote: 'The reviewer opted into subdomain matching under the same quorum gate.',
    advice: ['Do not interact with this fictional target.'],
    reason: 'Opting into subdomain matching for a shared-host subdomain is now supported.',
    indicators: [{ kind: 'domain', value: 'evil.vercel.app', matchSubdomains: true }],
  });
  const registry = buildCheckRegistry(mvp.listIncidents());
  assert.equal(matchCheckTarget(registry, { kind: 'domain', normalized: 'app.evil.vercel.app' }).length, 1);
  // The platform root itself still never matches.
  assert.equal(matchCheckTarget(registry, { kind: 'domain', normalized: 'vercel.app' }).length, 0);
});
