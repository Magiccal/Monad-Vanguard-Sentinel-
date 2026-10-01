import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { createSentinel } from '../src/core.mjs';
import { createApiServer } from '../src/server.mjs';
import { Store } from '../src/store.mjs';

const reportInput = () => ({
  reporterId: 'alice',
  chainId: 10143,
  contractAddress: '0x1111111111111111111111111111111111111111',
  title: 'Suspicious contract activity',
  description: 'A fictional community report with enough detail for a review.',
  evidence: [{
    kind: 'transaction',
    txHash: `0x${'a'.repeat(64)}`,
    note: 'Fictional transaction for a repeatable demonstration.',
  }],
});

test('submitted and rejected reports never become public alerts', async () => {
  const sentinel = createSentinel(await Store.open());
  const { id } = await sentinel.submit(reportInput());
  assert.deepEqual(sentinel.listAlerts(), []);
  assert.throws(() => sentinel.getAlert(id), { code: 'not_found' });
  assert.equal(sentinel.dashboardSummary().lastUpdatedAt, null);
  assert.equal(sentinel.listContributors()[0].pendingCount, 1);
  await sentinel.startReview(id, 'reviewer');
  assert.deepEqual(sentinel.listAlerts(), []);
  await sentinel.decide(id, 'reviewer', {
    outcome: 'rejected',
    reason: 'The fictional transaction does not substantiate the alleged contract risk.',
  });
  assert.deepEqual(sentinel.listAlerts(), []);
  assert.equal(sentinel.listContributors()[0].rejectedCount, 1);
  assert.throws(() => sentinel.getAlert(id), { code: 'not_found' });
});

test('verification, correction, and retraction keep a public audit trail', async () => {
  const sentinel = createSentinel(await Store.open());
  const { id } = await sentinel.submit(reportInput());
  await sentinel.startReview(id, 'reviewer');
  await sentinel.addEvidence(id, 'reviewer', {
    kind: 'public_source', url: 'https://example.org/fictional-notice',
    note: 'Fictional supporting source added by the reviewer during investigation.',
  });
  assert.equal(sentinel.getReport(id).evidence.length, 2);
  const approvedId = sentinel.getReport(id).evidence[0].id;
  await sentinel.decide(id, 'reviewer', {
    outcome: 'verified',
    classification: 'credible_threat',
    reason: 'The fictional evidence was manually accepted for the demonstration workflow.',
    advice: 'Avoid interacting with the fictional contract while investigating.',
    publicEvidenceIds: [approvedId],
  });
  assert.equal(sentinel.listAlerts().length, 1);
  assert.equal(sentinel.getAlert(id).version, 1);
  assert.equal(sentinel.getAlert(id).classification, 'credible_threat');
  assert.equal('reporterId' in sentinel.getAlert(id), false);
  assert.ok(sentinel.getAlert(id).evidence.every((item) => !('addedBy' in item)));
  assert.deepEqual(sentinel.getAlert(id).evidence.map((item) => item.id), [approvedId]);
  assert.equal(sentinel.getReport(id).evidence[0].addedBy, 'alice');

  await sentinel.correct(id, 'reviewer', {
    title: 'Updated fictional contract warning',
    advice: 'Review the fictional contract interactions before taking action.',
    reason: 'The initial demo warning wording overstated the available fictional evidence.',
    classification: 'confirmed_incident',
  });
  assert.equal(sentinel.getAlert(id).version, 2);
  assert.equal(sentinel.getAlert(id).classification, 'confirmed_incident');
  assert.equal(sentinel.getAlert(id).corrections.length, 1);

  await sentinel.retract(id, 'reviewer', {
    reason: 'Further fictional review showed the original warning should be withdrawn.',
  });
  assert.deepEqual(sentinel.listAlerts(), []);
  assert.equal(sentinel.listAlertHistory().length, 1);
  assert.equal(sentinel.dashboardSummary().retractedAlerts, 1);
  assert.equal(sentinel.getAlert(id).status, 'retracted');
  assert.equal(sentinel.getAlert(id).retraction.reason.includes('withdrawn'), true);
  assert.deepEqual(sentinel.listNotificationEvents().map((item) => item.kind), [
    'published', 'corrected', 'retracted',
  ]);
  assert.ok(sentinel.listNotificationEvents().every((item) => item.deliveryState === 'draft'));
  assert.deepEqual(sentinel.getReport(id).history.map((item) => item.type), [
    'submitted', 'review_started', 'evidence_added', 'verified', 'corrected', 'retracted',
  ]);
});

test('watchlist prevents duplicate active targets and preserves archived observations', async () => {
  const sentinel = createSentinel(await Store.open());
  const input = { chainId: 10143, address: '0x1111111111111111111111111111111111111111', label: 'Demo target' };
  const target = await sentinel.addWatchTarget('reviewer', input);
  await assert.rejects(sentinel.addWatchTarget('reviewer', input), { code: 'duplicate_watch_target' });
  await sentinel.recordWatchObservation(target.id, 'reviewer', {
    state: 'scanned', observedAt: '2026-09-28T12:00:00.000Z', chainId: 10143,
    previousBlock: null, fromBlock: '0x1', toBlock: '0x2', latestBlock: '0x2',
    hasMore: false, logCount: 0, duplicateCount: 0, samples: [], logKeys: [],
  });
  assert.equal(sentinel.listWatchTargets()[0].lastScannedBlock, '0x2');
  await assert.rejects(sentinel.recordWatchObservation(target.id, 'reviewer', {
    state: 'scanned', observedAt: '2026-09-28T12:00:01.000Z', chainId: 10143,
    previousBlock: null, fromBlock: '0x1', toBlock: '0x2', latestBlock: '0x2',
    hasMore: false, logCount: 0, duplicateCount: 0, samples: [], logKeys: [],
  }), { code: 'stale_watch_check' });
  await sentinel.archiveWatchTarget(target.id, 'reviewer', {
    reason: 'This fictional target is no longer needed for the local demonstration.',
  });
  assert.equal(sentinel.listWatchTargets()[0].active, false);
  assert.equal(sentinel.listWatchTargets()[0].observations.length, 1);
  await assert.rejects(sentinel.recordWatchObservation(target.id, 'reviewer', {
    state: 'scanned', observedAt: '2026-09-28T12:01:00.000Z', chainId: 10143,
    previousBlock: '0x2', fromBlock: '0x3', toBlock: '0x3', latestBlock: '0x3',
    hasMore: false, logCount: 0, duplicateCount: 0, samples: [], logKeys: [],
  }), { code: 'watch_target_archived' });
});

test('reviewer assignment and state transitions are enforced', async () => {
  const sentinel = createSentinel(await Store.open());
  const { id } = await sentinel.submit(reportInput());
  const evidenceId = sentinel.getReport(id).evidence[0].id;
  await assert.rejects(sentinel.startReview(id, 'alice'), { code: 'self_review' });
  await assert.rejects(sentinel.decide(id, 'reviewer', {
    outcome: 'verified',
    classification: 'credible_threat',
    reason: 'This is a sufficiently long fictional decision explanation.',
    advice: 'Avoid the fictional contract.',
    publicEvidenceIds: [evidenceId],
  }), { code: 'invalid_transition' });
  await sentinel.startReview(id, 'reviewer');
  assert.throws(() => sentinel.decide(id, 'reviewer', {
    outcome: 'verified', classification: 'credible_threat',
    reason: 'This is a sufficiently long fictional decision explanation.',
    advice: 'Avoid the fictional contract.',
  }), { code: 'invalid_input' });
  await assert.rejects(sentinel.decide(id, 'reviewer', {
    outcome: 'verified', classification: 'credible_threat',
    reason: 'This is a sufficiently long fictional decision explanation.',
    advice: 'Avoid the fictional contract.', publicEvidenceIds: ['unknown-evidence'],
  }), { code: 'invalid_input' });
  assert.throws(() => sentinel.decide(id, 'reviewer', {
    outcome: 'verified',
    reason: 'This is a sufficiently long fictional decision explanation.',
    advice: 'Avoid the fictional contract.',
    publicEvidenceIds: [evidenceId],
  }), { code: 'invalid_input' });
  await assert.rejects(sentinel.addEvidence(id, 'another-reviewer', {
    kind: 'transaction', txHash: `0x${'b'.repeat(64)}`,
    note: 'Fictional evidence from an unassigned reviewer.',
  }), { code: 'wrong_reviewer' });
  await assert.rejects(sentinel.decide(id, 'another-reviewer', {
    outcome: 'verified',
    classification: 'credible_threat',
    reason: 'This is a sufficiently long fictional decision explanation.',
    advice: 'Avoid the fictional contract.',
    publicEvidenceIds: [evidenceId],
  }), { code: 'wrong_reviewer' });
  assert.equal(sentinel.getReport(id).status, 'in_review');
});

test('file store preserves reports across restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-test-'));
  try {
    const file = join(directory, 'state.json');
    const first = createSentinel(await Store.open(file));
    const { id } = await first.submit(reportInput());
    const savedTarget = await first.addWatchTarget('reviewer', {
      chainId: 10143, address: '0x1111111111111111111111111111111111111111', label: 'Persisted demo target',
    });
    await first.recordWatchObservation(savedTarget.id, 'reviewer', {
      state: 'scanned', observedAt: '2026-10-01T00:00:00.000Z', chainId: 10143,
      previousBlock: null, fromBlock: '0x1', toBlock: '0x2', latestBlock: '0x2',
      hasMore: false, logCount: 1, duplicateCount: 0, samples: [],
      logKeys: [`0x${'c'.repeat(64)}:1`],
    });
    await first.startReview(id, 'reviewer');
    await first.decide(id, 'reviewer', {
      outcome: 'verified', classification: 'credible_threat',
      reason: 'Fictional evidence was accepted to test persisted notification events.',
      advice: 'Avoid interacting with the fictional contract during this test.',
      publicEvidenceIds: [first.getReport(id).evidence[0].id],
    });
    const second = createSentinel(await Store.open(file));
    assert.equal(second.getReport(id).status, 'verified');
    assert.equal(second.getReport(id).evidence.length, 1);
    assert.equal(second.listWatchTargets().length, 1);
    assert.equal(second.listWatchTargets()[0].lastScannedBlock, '0x2');
    assert.equal(second.listWatchTargets()[0].recentLogKeys.length, 1);
    assert.equal(second.listNotificationEvents().length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('HTTP API protects reviewer data and publishes only verified reports', async () => {
  const sentinel = createSentinel(await Store.open());
  const token = 'fictional-test-reviewer-token-12345';
  const server = createApiServer({
    sentinel, reviewerToken: token, reviewerId: 'reviewer',
    rpc: {
      async call(method) {
        if (method === 'eth_chainId') return '0x279f';
        if (method === 'eth_getTransactionByHash') return {
          hash: `0x${'a'.repeat(64)}`,
          to: '0x1111111111111111111111111111111111111111',
        };
        if (method === 'eth_getTransactionReceipt') return {
          transactionHash: `0x${'a'.repeat(64)}`, blockNumber: '0x123', status: '0x1',
        };
        if (method === 'eth_blockNumber') return '0x100';
        if (method === 'eth_getLogs') return [];
        throw new Error(`Unexpected RPC method: ${method}`);
      },
    },
  });
  const invoke = (method, url, body, headers = {}) => new Promise((resolve) => {
    const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]);
    Object.assign(req, { method, url, headers });
    const res = {
      headersSent: false,
      writeHead(status) { this.status = status; this.headersSent = true; },
      end(payload) { resolve({ status: this.status, body: JSON.parse(payload) }); },
    };
    server.emit('request', req, res);
  });
  const json = { 'content-type': 'application/json' };
  const auth = { ...json, authorization: `Bearer ${token}` };
  const created = await invoke('POST', '/v1/reports', reportInput(), json);
  assert.equal(created.status, 201);
  const { id } = created.body;
  assert.equal((await invoke('GET', '/v1/reports')).status, 401);
  assert.equal((await invoke('GET', '/v1/notifications/outbox')).status, 401);
  assert.equal((await invoke('GET', '/v1/contributors')).status, 401);
  assert.deepEqual((await invoke('GET', '/v1/alerts')).body.alerts, []);
  assert.equal((await invoke('GET', '/v1/dashboard')).body.activeAlerts, 0);

  assert.equal((await invoke('POST', `/v1/reports/${id}/review`, undefined, auth)).status, 200);
  const added = await invoke('POST', `/v1/reports/${id}/evidence`, {
    kind: 'public_source', url: 'https://example.org/notice',
    note: 'Fictional source added to the report during the review.',
  }, auth);
  assert.equal(added.status, 201);
  const checked = await invoke('POST', `/v1/reports/${id}/check-evidence`, undefined, auth);
  assert.equal(checked.status, 200);
  assert.equal(checked.body.findings[0].state, 'mined');
  assert.deepEqual((await invoke('GET', '/v1/alerts')).body.alerts, []);
  const decision = await invoke('POST', `/v1/reports/${id}/decision`, {
    outcome: 'verified',
    classification: 'credible_threat',
    reason: 'Fictional evidence was reviewed for the local API demonstration.',
    advice: 'Avoid interacting with this fictional contract during the demo.',
    publicEvidenceIds: [added.body.id],
  }, auth);
  assert.equal(decision.status, 200);
  const alerts = (await invoke('GET', '/v1/alerts')).body.alerts;
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].id, id);
  assert.equal(alerts[0].classification, 'credible_threat');
  assert.equal(checked.body.findings[0].directTargetMatch, true);
  assert.equal('reporterId' in alerts[0], false);
  assert.ok(alerts[0].evidence.every((item) => !('addedBy' in item)));
  assert.deepEqual(alerts[0].evidence.map((item) => item.id), [added.body.id]);
  assert.equal(alerts[0].onchainObservation, null);
  assert.equal((await invoke('GET', '/v1/dashboard')).body.credibleThreats, 1);
  assert.equal((await invoke('GET', '/v1/alerts/history')).body.alerts.length, 1);
  assert.equal((await invoke('GET', '/v1/notifications/outbox', undefined, auth)).body.events.length, 1);
  assert.equal((await invoke('GET', '/v1/contributors', undefined, auth)).body.contributors[0].verifiedCount, 1);

  const watch = await invoke('POST', '/v1/watchlist', {
    chainId: 10143, address: '0x1111111111111111111111111111111111111111', label: 'Demo target',
  }, auth);
  assert.equal(watch.status, 201);
  const firstCheck = await invoke('POST', `/v1/watchlist/${watch.body.id}/check`, undefined, auth);
  assert.equal(firstCheck.body.state, 'scanned');
  assert.equal(firstCheck.body.logCount, 0);
  const secondCheck = await invoke('POST', `/v1/watchlist/${watch.body.id}/check`, undefined, auth);
  assert.equal(secondCheck.body.state, 'up_to_date');
  const targets = (await invoke('GET', '/v1/watchlist', undefined, auth)).body.targets;
  assert.equal(targets.length, 1);
  assert.equal(targets[0].lastScannedBlock, '0x100');
  assert.equal(targets[0].observations.length, 1);
});
