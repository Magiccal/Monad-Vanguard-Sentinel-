import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMvpService } from '../src/mvp.mjs';
import { createSentinel } from '../src/core.mjs';
import { createApiServer } from '../src/server.mjs';
import { Store } from '../src/store.mjs';

const reviewers = [
  { id: 'reviewer-a', discordId: '111111111111111111', token: 'reviewer-a-test-secret-token-123456', isLead: false },
  { id: 'reviewer-b', discordId: '222222222222222222', token: 'reviewer-b-test-secret-token-123456', isLead: false },
  { id: 'lead', discordId: '333333333333333333', token: 'reviewer-lead-test-secret-token-1234', isLead: true },
];
const agents = [
  { id: 'scout-01', name: 'Scout Agent 01', token: 'scout-agent-01-test-secret-token-123' },
  { id: 'scout-02', name: 'Scout Agent 02', token: 'scout-agent-02-test-secret-token-123' },
];
const botToken = 'trusted-discord-bot-test-token-123456';
const transactionEvidence = { kind: 'transaction', reference: `0x${'a'.repeat(64)}`, note: 'Fictional on-chain observation for review.' };
const publicNarrative = {
  summary: 'Reviewers are assessing an agent-reported fictional security lead.',
  verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
};

function invoke(server, method, url, body, token, extraHeaders = {}) {
  return new Promise((resolve) => {
    const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]);
    Object.assign(req, { method, url, headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...extraHeaders,
    } });
    const res = {
      headersSent: false,
      writeHead(status) { this.status = status; this.headersSent = true; },
      end(payload) {
        const raw = payload === undefined ? '' : payload.toString();
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        resolve({ status: this.status, body: parsed });
      },
    };
    server.emit('request', req, res);
  });
}

async function buildServer({ withAgents = true, agentConfig = agents, agentHeaderFallback = null, agentHeaderFallbackFile = null } = {}) {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers, agents: withAgents ? agentConfig : [] });
  const server = createApiServer({
    sentinel: createSentinel(store), mvp, reviewers,
    agents: withAgents ? agentConfig : [], discordBotToken: botToken,
    agentHeaderFallback,
    agentHeaderFallbackFile,
  });
  return { store, mvp, server };
}

test('agent intake requires configuration, authenticates by token, and files private reports', async () => {
  const { server: unconfigured } = await buildServer({ withAgents: false });
  assert.equal((await invoke(unconfigured, 'POST', '/v1/agents/reports', { description: 'x' }, agents[0].token)).body.error, 'agents_not_configured');

  const { mvp, server } = await buildServer();
  const report = { description: 'Agent scout observed a fictional lookalike claim portal.', targets: [{ kind: 'url', value: 'https://lookalike.example.test/claim' }], evidence: [transactionEvidence] };
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report)).status, 401);
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report, 'wrong-token-wrong-token-wrong-token')).status, 401);
  assert.equal((await invoke(server, 'GET', '/v1/agents/me', undefined, 'wrong-token-wrong-token-wrong-token')).status, 401);

  // Identity is server-side: the payload may not carry one.
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', { ...report, agentId: 'scout-02' }, agents[0].token)).body.error, 'invalid_input');
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', { ...report, reporterId: 'x' }, agents[0].token)).body.error, 'invalid_input');
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', { description: '' }, agents[0].token)).body.error, 'invalid_input');
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', { ...report, incidentType: 'rug_pull_pull' }, agents[0].token)).body.error, 'invalid_input');

  const created = await invoke(server, 'POST', '/v1/agents/reports', report, agents[0].token);
  assert.equal(created.status, 201);
  assert.equal(created.body.id, 'R-0001');
  assert.equal(created.body.status, 'submitted');
  assert.equal(created.body.agentId, 'scout-01');
  const stored = mvp.getReport('R-0001', 'reviewer-a');
  assert.equal(stored.source, 'agent');
  assert.equal(stored.reporterAgentId, 'scout-01');
  assert.equal(stored.reporterDiscordId, null);
  assert.equal(stored.history[0].source, 'agent');

  // Agent A sees only its own reports; agent B sees none.
  const own = await invoke(server, 'GET', '/v1/agents/reports', undefined, agents[0].token);
  assert.deepEqual(own.body.reports.map((item) => item.id), ['R-0001']);
  assert.equal(own.body.reputation.reports, 1);
  const other = await invoke(server, 'GET', '/v1/agents/reports', undefined, agents[1].token);
  assert.deepEqual(other.body.reports, []);

  const me = await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token);
  assert.deepEqual(me.body.agent, { id: 'scout-01', name: 'Scout Agent 01' });
  assert.equal(me.body.reputation.score, 0);
  assert.equal(me.body.reputation.throttled, false);

  // Human Discord intake is unaffected by the agent feature.
  const discordReport = await invoke(server, 'POST', '/v1/discord/reports', { discordUserId: '444444444444444444', description: 'A human community report unrelated to agents.' }, botToken);
  assert.equal(discordReport.status, 201);
  const human = mvp.getReport(discordReport.body.id, 'reviewer-a');
  assert.equal(human.reporterAgentId, undefined);
});

test('reviewer queue exposes the agent identity and live reputation; publication raises the score', async () => {
  const { mvp, server } = await buildServer();
  const created = await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Agent scout flagged a fictional malicious contract drain.',
    targets: [{ kind: 'address', value: `0x${'b'.repeat(40)}` }],
    evidence: [transactionEvidence],
  }, agents[0].token);
  const evidenceId = mvp.getReport(created.body.id, 'reviewer-a').evidence[0].id;

  const listed = await invoke(server, 'GET', '/v1/mvp/reports', undefined, reviewers[0].token);
  const entry = listed.body.reports.find((item) => item.id === created.body.id);
  assert.equal(entry.reporterAgentId, 'scout-01');
  assert.equal(entry.reporterReputation.published, 0);
  assert.equal(entry.reporterReputation.score, 0);

  const proposal = await invoke(server, 'POST', `/v1/mvp/reports/${created.body.id}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'high', title: 'Fictional agent-verified drain warning',
    advice: ['Pause interactions with the fictional contract while reviewers confirm.'],
    reason: 'Agent evidence was independently checked and supports a credible threat.',
    publicEvidenceIds: [evidenceId],
  }, reviewers[0].token);
  assert.equal(proposal.body.status, 'pending');
  await invoke(server, 'POST', `/v1/mvp/proposals/${proposal.body.id}/approval`, undefined, reviewers[1].token);

  const me = await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token);
  assert.equal(me.body.reputation.published, 1);
  assert.equal(me.body.reputation.score, 3);
  assert.equal(me.body.reputation.throttled, false);

  // The public incident never exposes the agent identity.
  const incident = (await invoke(server, 'GET', '/v1/mvp/incidents')).body.incidents[0];
  assert.equal(JSON.stringify(incident).includes('scout-01'), false);
  assert.equal(JSON.stringify(incident).includes('Scout Agent'), false);
});

test('throttle is a ratio rule: rejected, dismissed and merged all count against the agent', async () => {
  const { server } = await buildServer();
  const file = async (description) => (await invoke(server, 'POST', '/v1/agents/reports', {
    description, targets: [{ kind: 'address', value: `0x${'c'.repeat(40)}` }], evidence: [transactionEvidence],
  }, agents[0].token)).body.id;
  const propose = async (id) => {
    const evidenceId = (await invoke(server, 'GET', `/v1/mvp/reports/${id}`, undefined, reviewers[0].token)).body.evidence[0].id;
    return (await invoke(server, 'POST', `/v1/mvp/reports/${id}/publication`, {
      ...publicNarrative,
      level: 'credible_threat', severity: 'low', title: 'Fictional agent report review',
      advice: ['Check official project channels while reviewers investigate.'],
      reason: 'This fictional proposal exists to exercise the rejection flow.',
      publicEvidenceIds: [evidenceId],
    }, reviewers[0].token)).body.id;
  };

  const r1 = await file('Agent report one pending fictional review.');
  const r2 = await file('Agent report two pending fictional review.');
  const r3 = await file('Agent report three duplicating the first lead.');
  for (const id of [r1, r2]) {
    const rejected = await invoke(server, 'POST', `/v1/mvp/proposals/${await propose(id)}/rejection`, {
      reason: 'Reviewers need more evidence before publishing this claim.',
    }, reviewers[1].token);
    assert.equal(rejected.body.status, 'rejected');
  }
  // Two rejections alone no longer throttle (ratio rule: negative >= published + 3).
  assert.equal((await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token)).body.reputation.throttled, false);

  // A merged (duplicate) report counts toward the negative factor.
  const merged = await invoke(server, 'POST', `/v1/mvp/reports/${r3}/merge`, {
    intoReportId: r1, reason: 'Duplicate of the first fictional agent report.',
  }, reviewers[0].token);
  assert.equal(merged.body.status, 'merged');
  const me = await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token);
  assert.equal(me.body.reputation.duplicates, 1);
  assert.equal(me.body.reputation.throttled, true);
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'A fourth report that should hit the ratio throttle.',
  }, agents[0].token)).body.error, 'agent_throttled');

  // The other agent is untouched.
  const other = await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'The second agent is unaffected by the first throttle.',
  }, agents[1].token);
  assert.equal(other.status, 201);
});

test('reviewer dismiss action closes a report and counts against the agent', async () => {
  const { server } = await buildServer();
  const r1 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'A spammy fictional report that reviewers will dismiss.',
  }, agents[0].token)).body.id;
  const r2 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Another fictional report headed for a rejection.',
    evidence: [transactionEvidence],
  }, agents[0].token)).body.id;

  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, { reason: 'short' }, reviewers[0].token)).body.error, 'invalid_input');
  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, { reason: 'Out of scope for this demo queue.' })).status, 401);
  const dismissed = await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, {
    reason: 'Fictional spam report dismissed by the reviewer on duty.',
  }, reviewers[0].token);
  assert.equal(dismissed.body.status, 'dismissed');
  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, { reason: 'Already dismissed once before this call here.' }, reviewers[0].token)).body.error, 'invalid_transition');

  const evidenceId = (await invoke(server, 'GET', `/v1/mvp/reports/${r2}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const proposal = (await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional agent report review',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'This fictional proposal exists to exercise the rejection flow.',
    publicEvidenceIds: [evidenceId],
  }, reviewers[0].token)).body.id;
  await invoke(server, 'POST', `/v1/mvp/proposals/${proposal}/rejection`, {
    reason: 'Reviewers need more evidence before publishing this claim.',
  }, reviewers[1].token);

  // dismissed counts as its own bucket and leaves the open count.
  const me = await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token);
  assert.equal(me.body.reputation.dismissed, 1);
  assert.equal(me.body.reputation.rejected, 1);
  assert.equal(me.body.reputation.open, 1); // a rejected report stays open for re-proposal
  assert.equal(me.body.reputation.throttled, false);
});

test('flood control: 10 reports per rolling hour, then agent_rate_limited', async () => {
  const { server } = await buildServer();
  for (let index = 0; index < 10; index += 1) {
    const created = await invoke(server, 'POST', '/v1/agents/reports', {
      description: `Fictional flood-control report number ${index + 1}.`,
    }, agents[0].token);
    assert.equal(created.status, 201, `report ${index + 1} should be accepted`);
  }
  const eleventh = await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'The eleventh report inside the same rolling hour.',
  }, agents[0].token);
  assert.equal(eleventh.status, 429);
  assert.equal(eleventh.body.error, 'agent_rate_limited');
});

test('open cap: 20 unprocessed reports block further submissions', async () => {
  let clock = Date.parse('2026-10-20T00:00:00.000Z');
  const now = () => new Date(clock).toISOString();
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers, agents, now });
  for (let index = 0; index < 20; index += 1) {
    clock += 3600000; // one report per hour: the rate limit never triggers
    const created = await mvp.submitAgentReport({ description: `Fictional backlog report number ${index + 1}.` }, 'scout-01');
    assert.equal(created.status, 'submitted');
  }
  clock += 3600000;
  await assert.rejects(() => mvp.submitAgentReport({ description: 'The twenty-first open fictional report.' }, 'scout-01'),
    { code: 'agent_open_cap' });
});

test('public text guards: the word "null" is fine, agent identity is not', async () => {
  const { server } = await buildServer();
  const r1 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Agent report whose public text mentions the word null legitimately.',
    evidence: [transactionEvidence],
  }, agents[0].token)).body.id;
  const evidenceId = (await invoke(server, 'GET', `/v1/mvp/reports/${r1}`, undefined, reviewers[0].token)).body.evidence[0].id;

  // "null" in the summary used to trip the includes(null) coercion bug.
  const ok = await invoke(server, 'POST', `/v1/mvp/reports/${r1}/publication`, {
    ...publicNarrative,
    summary: 'The parsed value was null while the fictional page rendered, which reviewers reviewed.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional null-word summary review',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'The word null in public text must not fail the identity guard.',
    publicEvidenceIds: [evidenceId],
  }, reviewers[0].token);
  assert.equal(ok.status, 200);

  // The agent's display name is blocked from public text.
  const r2 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Agent report for the identity guard test with evidence.',
    evidence: [transactionEvidence],
  }, agents[0].token)).body.id;
  const evidenceId2 = (await invoke(server, 'GET', `/v1/mvp/reports/${r2}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const leaked = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    summary: 'Filed by Scout Agent 01, an automated scout, and confirmed by reviewers.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional identity leak attempt',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Public text must not carry the agent display name.',
    publicEvidenceIds: [evidenceId2],
  }, reviewers[0].token);
  assert.equal(leaked.body.error, 'private_identity');

  // Ollie 2026-10-20 follow-up: the guard is case-insensitive — "SCOUT AGENT 01"
  // must not slip past a "Scout Agent 01" identity.
  const evidenceId3 = (await invoke(server, 'GET', `/v1/mvp/reports/${r2}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const leakedUpper = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    summary: 'Filed by SCOUT AGENT 01, an automated scout, and confirmed by reviewers.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional identity leak attempt',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Public text must not carry the agent display name in any case.',
    publicEvidenceIds: [evidenceId3],
  }, reviewers[0].token);
  assert.equal(leakedUpper.body.error, 'private_identity');

  // Ollie 2026-10-20 18:43: the hyphenated agent id also matches in any case,
  // while "Scout" alone stays fine.
  const evidenceId4 = (await invoke(server, 'GET', `/v1/mvp/reports/${r2}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const leakedHyphen = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    summary: 'Report scout 01 was checked and the fictional page was confirmed malicious.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional identity leak attempt',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Public text must not carry the agent id in any spelling.',
    publicEvidenceIds: [evidenceId4],
  }, reviewers[0].token);
  assert.equal(leakedHyphen.body.error, 'private_identity');
  const hyphenExact = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    summary: 'Report scout-01 was checked and the fictional page was confirmed malicious.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional identity leak attempt',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Public text must not carry the agent id in hyphen spelling.',
    publicEvidenceIds: [evidenceId4],
  }, reviewers[0].token);
  assert.equal(hyphenExact.body.error, 'private_identity');
  const scoutAlone = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    summary: 'A fictional scout page was reviewed and reviewers confirmed the phishing pattern.',
    verificationNote: 'The public level reflects the current human review and may change as evidence is checked.',
    level: 'credible_threat', severity: 'low', title: 'Fictional single-word summary',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'The word scout alone does not expose the reporter identity.',
    publicEvidenceIds: [evidenceId4],
  }, reviewers[0].token);
  assert.equal(scoutAlone.status, 200);
});

test('agent auth default is Bearer only: the fallback header is ignored while AGENT_TOKEN_HEADER_FALLBACK is off', async () => {
  const { server } = await buildServer();
  const report = { description: 'A fictional report sent with a fallback header.' };
  // Fallback header must not authenticate agents while the flag is off.
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token })).status, 401);
  // Bearer works.
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report, agents[0].token)).status, 201);
  // Agent tokens never authenticate reviewer endpoints, either header.
  assert.equal((await invoke(server, 'GET', '/v1/mvp/reports', undefined, agents[0].token)).status, 401);
  assert.equal((await invoke(server, 'GET', '/v1/mvp/reports', undefined, null, { 'x-sentinel-token': agents[0].token })).status, 401);
  assert.equal((await invoke(server, 'GET', '/v1/mvp/notifications/outbox', undefined, agents[0].token)).status, 401);
});

test('AGENT_TOKEN_HEADER_FALLBACK=true accepts the fallback header on agent routes only, Bearer always wins', async () => {
  const { server } = await buildServer({ agentHeaderFallback: true });
  const report = { description: 'A fictional report sent through the proxy workaround.' };
  // Fallback header authenticates the agent on agent routes.
  const viaFallback = await invoke(server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token });
  assert.equal(viaFallback.status, 201);
  assert.equal(viaFallback.body.agentId, 'scout-01');
  assert.equal((await invoke(server, 'GET', '/v1/agents/me', undefined, null, { 'x-sentinel-token': agents[0].token })).status, 200);
  // But never on reviewer routes, even with the flag on.
  assert.equal((await invoke(server, 'GET', '/v1/mvp/reports', undefined, null, { 'x-sentinel-token': agents[0].token })).status, 401);
  // Both headers: Bearer wins and the fallback is ignored — never both tried.
  const both = await invoke(server, 'POST', '/v1/agents/reports', report, agents[0].token, { 'x-sentinel-token': agents[1].token });
  assert.equal(both.status, 201);
  assert.equal(both.body.agentId, 'scout-01');
  // An invalid Bearer is not rescued by a valid fallback header.
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report, 'wrong-token-wrong-token-wrong-token', { 'x-sentinel-token': agents[0].token })).status, 401);
  assert.equal((await invoke(server, 'POST', '/v1/agents/reports', report, 'Basic not-a-bearer-value-here-12345', { 'x-sentinel-token': agents[0].token })).status, 401);
});

test('the flag file enables the fallback while the env var is unset (hosted sandbox workaround)', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'sentinel-flag-'));
  const flagFile = join(dir, 'agent-header-fallback.flag');
  const report = { description: 'A fictional report gated by the flag file.' };
  // No flag file: fallback stays off.
  const off = await buildServer({ agentHeaderFallbackFile: join(dir, 'absent.flag') });
  assert.equal((await invoke(off.server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token })).status, 401);
  // A "true" flag file turns the fallback on.
  await writeFile(flagFile, 'true\n');
  const on = await buildServer({ agentHeaderFallbackFile: flagFile });
  const viaFile = await invoke(on.server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token });
  assert.equal(viaFile.status, 201);
  assert.equal(viaFile.body.agentId, 'scout-01');
  // An explicit override wins over a "false" flag file.
  const overridden = await buildServer({ agentHeaderFallback: true, agentHeaderFallbackFile: flagFile });
  assert.equal((await invoke(overridden.server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token })).status, 201);
  // A "false" flag file keeps the fallback off.
  await writeFile(flagFile, 'false');
  const disabled = await buildServer({ agentHeaderFallbackFile: flagFile });
  assert.equal((await invoke(disabled.server, 'POST', '/v1/agents/reports', report, null, { 'x-sentinel-token': agents[0].token })).status, 401);
  await rm(dir, { recursive: true, force: true });
});

test('revoked agents are rejected outright, fallback header included', async () => {
  const revoked = [{ id: 'scout-01', name: 'Scout Agent 01', token: 'scout-agent-01-test-secret-token-123', revoked: true }];
  const { server } = await buildServer({ agentConfig: revoked, agentHeaderFallback: true });
  const first = await invoke(server, 'POST', '/v1/agents/reports', { description: 'A fictional report from a revoked agent.' }, revoked[0].token);
  assert.equal(first.status, 403);
  assert.equal(first.body.error, 'agent_revoked');
  assert.equal((await invoke(server, 'GET', '/v1/agents/me', undefined, revoked[0].token)).body.error, 'agent_revoked');
  const viaFallback = await invoke(server, 'POST', '/v1/agents/reports', { description: 'A revoked agent trying the fallback header.' }, null, { 'x-sentinel-token': revoked[0].token });
  assert.equal(viaFallback.status, 403);
  assert.equal(viaFallback.body.error, 'agent_revoked');
});

test('agent configuration is validated up front', async () => {
  const bad = [
    [{ id: 'x', name: 'Scout', token: 'short' }],
    [{ id: 'ok-agent', name: 'Scout', token: 'a'.repeat(24) }, { id: 'ok-agent', name: 'Scout 2', token: 'b'.repeat(24) }],
    [{ id: 'ok-agent', name: 'S', token: 'a'.repeat(24) }],
    [{ id: 'ok-agent', name: 'Scout', token: 'a'.repeat(24) }, { id: 'ok-agent-2', name: 'Scout 2', token: 'a'.repeat(24) }],
    // Ollie 2026-10-20 follow-up: display names are case-insensitively distinct.
    [{ id: 'ok-agent', name: 'Scout One', token: 'a'.repeat(24) }, { id: 'ok-agent-2', name: 'SCOUT ONE', token: 'b'.repeat(24) }],
  ];
  for (const agentConfig of bad) {
    assert.throws(() => createMvpService(Store.open(), { reviewers, agents: agentConfig }));
    assert.throws(() => createApiServer({ sentinel: createSentinel(Store.open()), reviewers, agents: agentConfig, mvp: createMvpService(Store.open(), { reviewers, agents: agentConfig }) }));
  }
  // A valid configuration constructs cleanly, and agent tokens may not collide
  // with reviewer or bot tokens.
  const ok = await buildServer();
  assert.ok(ok.mvp);
  assert.throws(() => createApiServer({
    sentinel: createSentinel(Store.open()), reviewers,
    agents: [{ id: 'ok-agent', name: 'Scout', token: reviewers[0].token }],
    mvp: createMvpService(Store.open(), { reviewers, agents: [{ id: 'ok-agent', name: 'Scout', token: reviewers[0].token }] }),
  }));
});

// Ollie 2026-10-20 follow-up: dismissing a report must not leave a pending
// proposal able to approve and publish afterwards, and a dismissed report is
// inert until a reviewer explicitly reopens it.
test('dismiss is blocked while a proposal is pending; dismissed reports need an explicit reopen', async () => {
  const { server } = await buildServer();
  const r1 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Fictional report with a pending publication proposal.',
    evidence: [transactionEvidence],
  }, agents[0].token)).body.id;
  const r2 = (await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'Fictional report dismissed before any proposal exists.',
    evidence: [transactionEvidence],
  }, agents[0].token)).body.id;

  // Pending proposal blocks dismiss.
  const evidenceId1 = (await invoke(server, 'GET', `/v1/mvp/reports/${r1}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const pending = (await invoke(server, 'POST', `/v1/mvp/reports/${r1}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional pending publication',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'This pending proposal must block the dismiss action.',
    publicEvidenceIds: [evidenceId1],
  }, reviewers[0].token)).body.id;
  const blocked = await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, {
    reason: 'Reviewer tries to dismiss while the proposal is pending.',
  }, reviewers[0].token);
  assert.equal(blocked.status, 409);
  assert.equal(blocked.body.error, 'proposal_pending');

  // After the proposal is rejected, dismiss goes through.
  await invoke(server, 'POST', `/v1/mvp/proposals/${pending}/rejection`, {
    reason: 'Rejected so the dismiss action can proceed in this test.',
  }, reviewers[1].token);
  const dismissed = await invoke(server, 'POST', `/v1/mvp/reports/${r1}/dismiss`, {
    reason: 'Dismissed after the pending proposal was rejected.',
  }, reviewers[0].token);
  assert.equal(dismissed.body.status, 'dismissed');

  // A dismissed report cannot be proposed; reopen is explicit.
  const evidenceId2 = (await invoke(server, 'GET', `/v1/mvp/reports/${r2}`, undefined, reviewers[0].token)).body.evidence[0].id;
  // Reopen only applies to dismissed reports — r2 is still submitted here.
  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${r2}/reopen`, undefined, reviewers[0].token)).body.error, 'invalid_transition');
  await invoke(server, 'POST', `/v1/mvp/reports/${r2}/dismiss`, {
    reason: 'Dismissed up front so the reopen path can be tested.',
  }, reviewers[0].token);
  const proposedWhileDismissed = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional dismissed proposal',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Proposing on a dismissed report must fail outright.',
    publicEvidenceIds: [evidenceId2],
  }, reviewers[0].token);
  assert.equal(proposedWhileDismissed.status, 409);
  assert.equal(proposedWhileDismissed.body.error, 'report_dismissed');

  // Reopen is explicit, then proposing works again.
  const reopened = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/reopen`, undefined, reviewers[0].token);
  assert.equal(reopened.body.status, 'submitted');
  const proposedAfterReopen = await invoke(server, 'POST', `/v1/mvp/reports/${r2}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional reopened proposal',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'After an explicit reopen the report is proposable again.',
    publicEvidenceIds: [evidenceId2],
  }, reviewers[0].token);
  assert.equal(proposedAfterReopen.status, 200);
  assert.equal(proposedAfterReopen.body.status, 'pending');
});

// Ollie 2026-10-20 follow-up: a duplicate stops counting against the agent once
// the canonical report it was merged into gets published — the intel was right.
test('duplicate no longer penalizes the agent once the canonical report is published', async () => {
  const { server } = await buildServer();
  const file = async (description) => (await invoke(server, 'POST', '/v1/agents/reports', {
    description, targets: [{ kind: 'address', value: `0x${'d'.repeat(40)}` }], evidence: [transactionEvidence],
  }, agents[0].token)).body.id;
  const canonical = await file('Canonical fictional agent report later published.');
  const duplicate = await file('Duplicate fictional report merged into the canonical one.');

  await invoke(server, 'POST', `/v1/mvp/reports/${duplicate}/merge`, {
    intoReportId: canonical, reason: 'Merged as a duplicate of the canonical report.',
  }, reviewers[0].token);
  assert.equal((await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token)).body.reputation.duplicates, 1);

  const evidenceId = (await invoke(server, 'GET', `/v1/mvp/reports/${canonical}`, undefined, reviewers[0].token)).body.evidence[0].id;
  const proposal = (await invoke(server, 'POST', `/v1/mvp/reports/${canonical}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional canonical publication',
    advice: ['Check official project channels while reviewers investigate.'],
    reason: 'Publishing the canonical clears the duplicate penalty.',
    publicEvidenceIds: [evidenceId],
  }, reviewers[0].token)).body.id;
  await invoke(server, 'POST', `/v1/mvp/proposals/${proposal}/approval`, undefined, reviewers[1].token);

  const me = (await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token)).body.reputation;
  assert.equal(me.published, 1);
  assert.equal(me.duplicates, 0);
  assert.equal(me.score, 3);
  assert.equal(me.throttled, false);
});
