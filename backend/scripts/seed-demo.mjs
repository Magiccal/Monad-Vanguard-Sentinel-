// Idempotent demo seed: fills the store with fictional hosted-demo content.
// Skips automatically when reports already exist, so it is safe to run on every boot.
// Usage: DATA_FILE=./data/sentinel.json npm run seed
import { resolve } from 'node:path';
import { Store } from '../src/store.mjs';
import { createMvpService } from '../src/mvp.mjs';

const file = resolve(process.env.DATA_FILE || './data/sentinel.json');
const store = await Store.open(file);
const hasReports = store.read((state) => (state.mvp?.reports?.length ?? 0) > 0);
if (hasReports) {
  console.log(`Seed skipped: ${file} already contains reports.`);
} else {
  let step = 0;
  const now = () => new Date(Date.parse('2026-10-06T00:00:00.000Z') + (step++) * 1800000).toISOString();
  // Single configured reviewer -> demo_single_reviewer mode; hosted demo only.
  const mvp = createMvpService(store, { now, reviewers: [{ id: 'demo-reviewer', discordId: '100000000000000001' }] });

  // R-0001 -> under_investigation (published)
  await mvp.submitDiscord({
    description: 'The verification portal of a fictional Monad testnet dapp started asking visitors to connect a wallet and sign a "free testnet points upgrade" message. The domain was registered two days ago and mimics the official one.',
    incidentType: 'phishing',
    targets: [{ kind: 'url', value: 'https://fictional-points-upgrade.example' }],
    evidence: [{ kind: 'official_statement', reference: 'https://fictional-project.example/announcements/domain-warning', note: 'Fictional registrar record showing a two-day-old creation date.' }],
  }, '200000000000000001');
  const r1 = mvp.listReports('demo-reviewer')[0];
  await mvp.proposeFromReport(r1.id, 'demo-reviewer', {
    level: 'under_investigation', severity: 'medium',
    title: 'Fictional points-upgrade portal under review',
    summary: 'A community member reported a lookalike "points upgrade" portal for a fictional Monad dapp. We are checking the domain age and any related activity before escalating.',
    verificationNote: 'Domain-age check and reporter screenshots reviewed by the demo reviewer.',
    advice: ['Do not sign messages on lookalike portals.', 'Use the official project site only.'],
    reason: 'Escalating to under investigation so the community treats the lookalike portal with caution while we verify.',
    publicEvidenceIds: r1.evidence.map((item) => item.id),
  });

  // R-0002 -> credible_threat (high): fictional Velunor fake claim site, matches the demo video and Metropolis write-up
  await mvp.submitDiscord({
    description: 'DEMO CONTENT. A fake claim site for the fictional Velunor project is asking users to connect their wallets. Velunor is fictional and used only for this demonstration.',
    incidentType: 'phishing',
    targets: [{ kind: 'url', value: 'https://velunor-claim.xyz' }],
    evidence: [{ kind: 'official_statement', reference: 'https://velunor.example/announcements/fake-claim-warning', note: 'Fictional Velunor warning about the fake claim site, used for the demo.' }],
  }, '200000000000000002');
  const r2 = mvp.listReports('demo-reviewer')[1];
  await mvp.proposeFromReport(r2.id, 'demo-reviewer', {
    level: 'credible_threat', severity: 'high',
    title: 'Fake Velunor ($VLN) claim site',
    summary: 'DEMO CONTENT. A fake Velunor claim site, velunor-claim[.]xyz, is asking users to connect their wallets. Velunor is a fictional project used only for this demonstration.',
    verificationNote: 'Reporter screenshots and the fake claim page were reviewed before publication.',
    advice: ['Do not connect your wallet to velunor-claim[.]xyz.', 'If you connected, revoke any approvals you gave the site now.', 'Only trust links posted in Velunor\'s official channels.'],
    reason: 'Publishing as a credible threat because the fake claim page actively requests wallet connections.',
    publicEvidenceIds: r2.evidence.map((item) => item.id),
  });

  // R-0003 -> informational (published)
  await mvp.submitDiscord({
    description: 'A fictional NFT project announced a mint before publishing a contract address.',
    incidentType: 'not_sure',
    targets: [{ kind: 'x_handle', value: '@fictional_mint' }],
  }, '200000000000000003');
  const r3 = mvp.listReports('demo-reviewer')[2];
  await mvp.proposeFromReport(r3.id, 'demo-reviewer', {
    level: 'informational', severity: null,
    title: 'Fictional NFT mint announcement without a contract address',
    summary: 'A fictional NFT project announced a mint before publishing a contract address. Informational only; no evidence of harm.',
    verificationNote: 'Announcement checked against the fictional project profile.',
    advice: ['Wait for the official contract address before interacting with any mint link.'],
    reason: 'Publishing as informational so the community knows the announcement exists without implying any risk.',
  });

  // R-0004 stays private on purpose: it demonstrates that unreviewed reports never publish.
  await mvp.submitDiscord({
    description: 'A fictional rumor about a token launch, submitted for the demo to show that private reports stay private until a reviewer publishes.',
  }, '200000000000000004');

  const incidents = store.read((state) => state.mvp.incidents.map((item) => `${item.id}:${item.level}`));
  console.log(`Seeded ${file}: 4 private reports, ${incidents.length} public incidents (${incidents.join(', ')}), 1 report kept private.`);
}
