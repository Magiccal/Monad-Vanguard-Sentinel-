import { createMvpService } from '../src/mvp.mjs';
import { Store } from '../src/store.mjs';

const reviewers = [
  { id: 'fictional-reviewer-a', discordId: '111111111111111111', isLead: false },
  { id: 'fictional-reviewer-b', discordId: '222222222222222222', isLead: false },
  { id: 'fictional-lead', discordId: '333333333333333333', isLead: true },
];
const mvp = createMvpService(await Store.open(), { reviewers });
const report = await mvp.submitDiscord({
  description: 'A fictional claim link is impersonating a project. The reporter did not connect a wallet.',
  incidentType: 'phishing',
  targets: [{ kind: 'url', value: 'https://claim.example.test/reward?campaign=fictional' }],
  evidence: [{ kind: 'official_statement', reference: 'https://project.example.test/notice', note: 'Fictional source for this local demonstration.' }],
}, '444444444444444444');
console.log('Private receipt:', report);
console.log('Public before review:', mvp.listIncidents());
const evidenceId = mvp.getReport(report.id, reviewers[0].id).evidence[0].id;
const proposed = await mvp.proposeFromReport(report.id, reviewers[0].id, {
  level: 'credible_threat', severity: 'high', title: 'Fictional claim link warning',
  summary: 'A fictional claim page is impersonating the project and asking visitors to connect wallets.',
  verificationNote: 'Two reviewers compared the report with a fictional project notice; this is a local demo.',
  advice: 'Avoid the claim link and check the official project channels for updates.',
  reason: 'Two reviewers are checking a fictional official notice before publication.',
  publicEvidenceIds: [evidenceId],
});
console.log('After first approval:', { status: proposed.status, publicIncidents: mvp.listIncidents().length });
const approved = await mvp.approveProposal(proposed.id, reviewers[1].id);
console.log('After second approval:', approved.publishedIncident);
console.log('Discord notification drafts:', mvp.listNotificationEvents(reviewers[0].id).length);
