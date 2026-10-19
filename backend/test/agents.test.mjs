import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
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

function invoke(server, method, url, body, token) {
  return new Promise((resolve) => {
    const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]);
    Object.assign(req, { method, url, headers: {
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
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

async function buildServer({ withAgents = true, agentConfig = agents } = {}) {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers, agents: withAgents ? agentConfig : [] });
  const server = createApiServer({
    sentinel: createSentinel(store), mvp, reviewers,
    agents: withAgents ? agentConfig : [], discordBotToken: botToken,
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

test('two rejected proposals with no publication throttle the agent', async () => {
  const { server } = await buildServer();
  const file = async (description) => (await invoke(server, 'POST', '/v1/agents/reports', {
    description, targets: [{ kind: 'address', value: `0x${'c'.repeat(40)}` }], evidence: [transactionEvidence],
  }, agents[0].token)).body.id;

  for (const description of ['Agent report one pending fictional review.', 'Agent report two pending fictional review.']) {
    const id = await file(description);
    const evidenceId = (await invoke(server, 'GET', `/v1/mvp/reports/${id}`, undefined, reviewers[0].token)).body.evidence[0].id;
    const proposal = await invoke(server, 'POST', `/v1/mvp/reports/${id}/publication`, {
      ...publicNarrative,
      level: 'credible_threat', severity: 'low', title: 'Fictional agent report review',
      advice: ['Check official project channels while reviewers investigate.'],
      reason: 'This fictional proposal exists to exercise the rejection flow.',
      publicEvidenceIds: [evidenceId],
    }, reviewers[0].token);
    const rejected = await invoke(server, 'POST', `/v1/mvp/proposals/${proposal.body.id}/rejection`, {
      reason: 'Reviewers need more evidence before publishing this claim.',
    }, reviewers[1].token);
    assert.equal(rejected.body.status, 'rejected');
  }

  const me = await invoke(server, 'GET', '/v1/agents/me', undefined, agents[0].token);
  assert.equal(me.body.reputation.rejected, 2);
  assert.equal(me.body.reputation.throttled, true);

  const throttled = await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'A third report that should hit the throttle gate.',
  }, agents[0].token);
  assert.equal(throttled.status, 429);
  assert.equal(throttled.body.error, 'agent_throttled');

  // The other agent is untouched.
  const other = await invoke(server, 'POST', '/v1/agents/reports', {
    description: 'The second agent is unaffected by the first throttle.',
  }, agents[1].token);
  assert.equal(other.status, 201);
});

test('agent configuration is validated up front', async () => {
  const bad = [
    [{ id: 'x', name: 'Scout', token: 'short' }],
    [{ id: 'ok-agent', name: 'Scout', token: 'a'.repeat(24) }, { id: 'ok-agent', name: 'Scout 2', token: 'b'.repeat(24) }],
    [{ id: 'ok-agent', name: 'S', token: 'a'.repeat(24) }],
    [{ id: 'ok-agent', name: 'Scout', token: 'a'.repeat(24) }, { id: 'ok-agent-2', name: 'Scout 2', token: 'a'.repeat(24) }],
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
