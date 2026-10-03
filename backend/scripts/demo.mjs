import { createSentinel } from '../src/core.mjs';
import { Store } from '../src/store.mjs';

const sentinel = createSentinel(await Store.open());
const submitted = await sentinel.submit({
  reporterId: 'community-member',
  chainId: 10143,
  contractAddress: '0x1111111111111111111111111111111111111111',
  title: 'Demo: suspicious contract activity',
  description: 'A fictional report for testing the review workflow; no real contract is accused.',
  evidence: [{
    kind: 'transaction',
    txHash: `0x${'a'.repeat(64)}`,
    note: 'Fictional transaction hash used only in the local demonstration.',
  }],
});

console.log('After submission, public alerts:', sentinel.listAlerts());
await sentinel.startReview(submitted.id, 'demo-reviewer');
await sentinel.addEvidence(submitted.id, 'demo-reviewer', {
  kind: 'public_source',
  url: 'https://example.org/fictional-notice',
  note: 'Fictional public notice added during the demonstration review.',
});
const publicEvidenceIds = sentinel.getReport(submitted.id).evidence.map((item) => item.id);
await sentinel.decide(submitted.id, 'demo-reviewer', {
  outcome: 'verified',
  classification: 'credible_threat',
  reason: 'Demo reviewer accepted the fictional evidence for workflow demonstration only.',
  advice: 'Do not interact with this fictional contract in the demo scenario.',
  publicEvidenceIds,
});
console.log('After verification, public alerts:', JSON.stringify(sentinel.listAlerts(), null, 2));

await sentinel.correct(submitted.id, 'demo-reviewer', {
  title: 'Demo: updated fictional contract warning',
  advice: 'Read the updated fictional warning before interacting with this demo contract.',
  reason: 'The wording was adjusted after a second review of the fictional evidence.',
  classification: 'confirmed_incident',
});
console.log('After correction, alert version:', sentinel.getAlert(submitted.id).version);
console.log('After reclassification:', sentinel.getAlert(submitted.id).classification);

await sentinel.retract(submitted.id, 'demo-reviewer', {
  reason: 'The fictional warning is withdrawn to demonstrate the retraction workflow.',
});
console.log('After retraction, public alerts:', sentinel.listAlerts());
console.log('Retracted alert remains addressable:', sentinel.getAlert(submitted.id).status);

const rejected = await sentinel.submit({
  reporterId: 'another-community-member',
  chainId: 10143,
  contractAddress: '0x2222222222222222222222222222222222222222',
  title: 'Demo: unsupported contract claim',
  description: 'A second fictional report demonstrates a claim that should not become public.',
  evidence: [{
    kind: 'transaction',
    txHash: `0x${'b'.repeat(64)}`,
    note: 'Fictional evidence does not substantiate the alleged issue.',
  }],
});
await sentinel.startReview(rejected.id, 'demo-reviewer');
await sentinel.decide(rejected.id, 'demo-reviewer', {
  outcome: 'rejected',
  reason: 'The fictional evidence does not support a public warning about this contract.',
});
console.log('Rejected report remains private:', sentinel.getReport(rejected.id).status);
