import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createSentinel } from '../src/core.mjs';
import { inspectWatchTarget } from '../src/rpc.mjs';
import { Store } from '../src/store.mjs';

async function example(name) {
  return JSON.parse(await readFile(new URL(`../examples/${name}.json`, import.meta.url), 'utf8'));
}

test('fictional integration examples match the report, alert, outbox, and watch APIs', async () => {
  const [reportInput, receiptExample, decisionInput, alertExample, outboxExample, watchExample, errorExample,
    unauthorizedExample, conflictExample, rpcUnavailableExample] = await Promise.all([
    example('report-request'), example('report-created'), example('review-decision-request'),
    example('alerts-response'), example('notification-outbox-response'),
    example('watch-check-response'), example('error-response'),
    example('unauthorized-response'), example('conflict-response'), example('rpc-not-configured-response'),
  ]);
  assert.deepEqual([unauthorizedExample.error, conflictExample.error, rpcUnavailableExample.error], [
    'unauthorized', 'invalid_transition', 'rpc_not_configured',
  ]);
  const sentinel = createSentinel(await Store.open(), { now: () => '2026-10-01T00:00:00.000Z' });
  const receipt = await sentinel.submit(reportInput);
  assert.deepEqual(Object.keys(receipt).sort(), Object.keys(receiptExample).sort());
  assert.equal(receipt.status, receiptExample.status);
  assert.equal(alertExample.alerts[0].id, receiptExample.id);
  assert.equal(outboxExample.events[0].alertId, receiptExample.id);
  assert.deepEqual(decisionInput.publicEvidenceIds, [alertExample.alerts[0].evidence[0].id]);

  await sentinel.startReview(receipt.id, 'demo-reviewer');
  const evidenceId = sentinel.getReport(receipt.id).evidence[0].id;
  await sentinel.decide(receipt.id, 'demo-reviewer', {
    ...decisionInput, publicEvidenceIds: [evidenceId],
  });
  const alert = sentinel.listAlerts()[0];
  assert.deepEqual(Object.keys(alert).sort(), Object.keys(alertExample.alerts[0]).sort());
  assert.equal(alert.title, alertExample.alerts[0].title);
  assert.equal(alert.contractAddress, alertExample.alerts[0].contractAddress);
  assert.equal(alert.evidence[0].txHash, alertExample.alerts[0].evidence[0].txHash);
  const outbox = sentinel.listNotificationEvents()[0];
  assert.deepEqual(Object.keys(outbox).sort(), Object.keys(outboxExample.events[0]).sort());
  assert.equal(outbox.kind, outboxExample.events[0].kind);
  assert.equal(outbox.deliveryState, 'draft');

  assert.throws(() => sentinel.submit({ ...reportInput, evidence: [] }), {
    code: errorExample.error, message: errorExample.message,
  });

  const rpc = {
    async call(method) {
      if (method === 'eth_chainId') return '0x279f';
      if (method === 'eth_blockNumber') return '0x100';
      return [{
        address: reportInput.contractAddress, transactionHash: reportInput.evidence[0].txHash,
        blockNumber: '0xff', blockHash: watchExample.samples[0].blockHash,
        logIndex: '0x1', topics: [],
      }];
    },
  };
  const result = await inspectWatchTarget({ chainId: 10143, address: reportInput.contractAddress }, rpc, {
    now: () => watchExample.observedAt,
  });
  const { logKeys, previousBlock, ...response } = result;
  assert.equal(logKeys.length, 1);
  assert.equal(previousBlock, null);
  assert.deepEqual(response, watchExample);
});
