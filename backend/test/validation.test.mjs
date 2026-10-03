import test from 'node:test';
import assert from 'node:assert/strict';
import {
  detectSensitiveMaterial, inspectPublicSourceUrl, normalizeAddress, normalizeTransactionHash,
} from '../src/validation.mjs';
import { createSentinel } from '../src/core.mjs';
import { Store } from '../src/store.mjs';

const reportInput = () => ({
  reporterId: 'alice', chainId: 10143,
  contractAddress: '0x1111111111111111111111111111111111111111',
  title: 'Suspicious contract activity',
  description: 'A fictional report with enough detail for a manual reviewer.',
  evidence: [{ kind: 'transaction', txHash: `0x${'a'.repeat(64)}`, note: 'Fictional transaction evidence.' }],
});

test('shared validators normalize valid values and reject malformed input', () => {
  assert.equal(normalizeAddress(`0x${'Ab'.repeat(20)}`), `0x${'ab'.repeat(20)}`);
  assert.equal(normalizeAddress('0x1234'), null);
  assert.equal(normalizeTransactionHash(`0x${'Ab'.repeat(32)}`), `0x${'ab'.repeat(32)}`);
  assert.equal(normalizeTransactionHash(`0x${'a'.repeat(40)}`), null);
  assert.deepEqual(inspectPublicSourceUrl('https://example.org/notice'), { url: 'https://example.org/notice' });
  assert.deepEqual(inspectPublicSourceUrl('not a URL'), { error: 'invalid' });
  assert.deepEqual(inspectPublicSourceUrl('https://example.org/notice?token=secret'), { error: 'unsafe' });
});

test('sensitive-content guard catches labeled secrets without blocking normal reports or transaction hashes', async () => {
  const sentinel = createSentinel(await Store.open());
  const privateKey = 'a'.repeat(64);
  const mnemonic = Array(12).fill('example').join(' ');
  assert.equal(detectSensitiveMaterial(`private key: 0x${privateKey}`), 'private_key');
  assert.equal(detectSensitiveMaterial(`seed phrase: ${mnemonic}`), 'seed_phrase');
  assert.equal(detectSensitiveMaterial(`私钥：0x${privateKey}`), 'private_key');
  assert.equal(detectSensitiveMaterial(`助记词：${mnemonic}`), 'seed_phrase');
  assert.equal(detectSensitiveMaterial('Never paste your seed phrase or private key into a report.'), null);
  assert.equal(detectSensitiveMaterial(`Transaction hash: 0x${privateKey}`), null);

  assert.throws(() => sentinel.submit({ ...reportInput(), description: `My private key: 0x${privateKey}` }), {
    code: 'sensitive_content',
  });
  assert.throws(() => sentinel.submit({ ...reportInput(), description: `seed phrase: ${mnemonic}` }), {
    code: 'sensitive_content',
  });
  assert.throws(() => sentinel.submit({
    ...reportInput(), evidence: [{ ...reportInput().evidence[0], note: `private key: ${privateKey}` }],
  }), { code: 'sensitive_content' });

  const normal = reportInput();
  normal.description = `Never paste your seed phrase or private key here. Transaction: 0x${privateKey}`;
  const { id } = await sentinel.submit(normal);
  assert.equal(sentinel.getReport(id).evidence[0].txHash, normal.evidence[0].txHash);
  await sentinel.startReview(id, 'reviewer');
  await assert.rejects(sentinel.addEvidence(id, 'reviewer', {
    kind: 'public_source', url: 'https://example.org/notice', note: `私钥：${privateKey}`,
  }), { code: 'sensitive_content' });
  assert.equal(sentinel.getReport(id).evidence.length, 1);
});

test('reviewer text that could become public rejects labeled secrets', async () => {
  const sentinel = createSentinel(await Store.open());
  const { id } = await sentinel.submit(reportInput());
  await sentinel.startReview(id, 'reviewer');
  const evidenceId = sentinel.getReport(id).evidence[0].id;
  const decision = {
    outcome: 'verified', classification: 'credible_threat',
    reason: 'The fictional evidence was manually reviewed for this test.',
    advice: 'Avoid this fictional contract while the review is active.',
    publicEvidenceIds: [evidenceId],
  };
  const privateKey = 'b'.repeat(64);
  assert.throws(() => sentinel.decide(id, 'reviewer', {
    ...decision, advice: `Do not use private key: 0x${privateKey}`,
  }), { code: 'sensitive_content' });
  assert.equal(sentinel.getReport(id).status, 'in_review');
  await sentinel.decide(id, 'reviewer', decision);
  assert.throws(() => sentinel.correct(id, 'reviewer', {
    title: 'Updated fictional contract warning',
    advice: 'Avoid this fictional contract during the review.',
    reason: `Removed private key: 0x${privateKey} from the public notice.`,
  }), { code: 'sensitive_content' });
  assert.throws(() => sentinel.retract(id, 'reviewer', {
    reason: `Retracted because private key: 0x${privateKey} appeared in the notice.`,
  }), { code: 'sensitive_content' });
  assert.equal(sentinel.getAlert(id).version, 1);
});
