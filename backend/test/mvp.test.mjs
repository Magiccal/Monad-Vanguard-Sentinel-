import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
const botToken = 'trusted-discord-bot-test-token-123456';
const reporterDiscordId = '444444444444444444';
const transactionEvidence = { kind: 'transaction', reference: `0x${'a'.repeat(64)}`, note: 'Fictional transaction pending human review.' };
const publicNarrative = {
  summary: 'Reviewers are assessing a fictional report about a possible project security issue.',
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
      end(payload) { resolve({ status: this.status, body: JSON.parse(payload) }); },
    };
    server.emit('request', req, res);
  });
}

test('trusted Discord submissions require only description and stay private before review', async () => {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers, discordBotToken: botToken });
  const input = {
    discordUserId: reporterDiscordId,
    description: 'A suspicious message about a fictional claim.',
    targets: [{ kind: 'url', value: 'https://claim.example.test/claim?token=demo#step1' }],
  };
  assert.equal((await invoke(server, 'POST', '/v1/discord/reports', input)).status, 401);
  assert.equal((await invoke(server, 'POST', '/v1/reports', {}, botToken)).status, 410);
  assert.equal((await invoke(server, 'GET', '/v1/alerts')).status, 410);
  assert.equal((await invoke(server, 'GET', '/')).status, 410);
  assert.equal((await invoke(server, 'GET', '/openapi.json')).status, 410);
  assert.equal((await invoke(server, 'POST', '/v1/discord/reports', { ...input, reporterName: 'fake' }, botToken)).status, 400);
  const created = await invoke(server, 'POST', '/v1/discord/reports', input, botToken);
  assert.equal(created.status, 201);
  assert.equal(created.body.id, 'R-0001');
  assert.equal(created.body.status, 'submitted');
  assert.deepEqual((await invoke(server, 'GET', '/v1/mvp/incidents')).body.incidents, []);
  assert.equal((await invoke(server, 'GET', `/v1/mvp/reports/${created.body.id}`)).status, 401);
  const privateReport = await invoke(server, 'GET', `/v1/mvp/reports/${created.body.id}`, undefined, reviewers[0].token);
  assert.equal(privateReport.status, 200);
  assert.equal(privateReport.body.incidentType, 'not_sure');
  assert.equal(privateReport.body.reporterDiscordId, reporterDiscordId);
  assert.equal(privateReport.body.targets[0].value, input.targets[0].value);
  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${created.body.id}/publication`, {
    ...publicNarrative, summary: input.description,
    level: 'informational', severity: null, title: 'Fictional suspicious claim reported',
    advice: 'Check official channels for updates before interacting with the claim.',
    reason: 'The report description is private and should not be copied verbatim.',
  }, reviewers[0].token)).body.error, 'private_report_copy');
  assert.equal((await invoke(server, 'POST', '/v1/discord/reports/status', { discordUserId: reporterDiscordId })).status, 401);
  const ownStatus = await invoke(server, 'POST', '/v1/discord/reports/status', { discordUserId: reporterDiscordId }, botToken);
  assert.deepEqual(ownStatus.body.reports.map((item) => item.id), [created.body.id]);
  assert.equal(JSON.stringify(ownStatus.body).includes(input.description), false);
  assert.deepEqual((await invoke(server, 'POST', '/v1/discord/reports/status', { discordUserId: '555555555555555555' }, botToken)).body.reports, []);
  assert.equal((await invoke(server, 'POST', `/v1/mvp/reports/${created.body.id}/triage`, {}, reviewers[0].token)).status, 200);
  const proposal = await invoke(server, 'POST', `/v1/mvp/reports/${created.body.id}/publication`, {
    ...publicNarrative,
    level: 'informational', severity: null, title: 'Fictional suspicious claim reported',
    advice: 'Check the official project channels and avoid connecting a wallet to that link.',
    reason: 'This is a community-submitted lead without independent confirmation.',
  }, reviewers[0].token);
  assert.equal(proposal.status, 200);
  assert.equal(proposal.body.status, 'published');
  assert.equal(proposal.body.publishedIncident.id, 'SEN-0001');
  const publicIncident = (await invoke(server, 'GET', '/v1/mvp/incidents')).body.incidents[0];
  assert.equal(publicIncident.level, 'informational');
  assert.equal(publicIncident.severity, null);
  assert.equal(publicIncident.approvalMode, 'three_reviewer_quorum');
  assert.match(publicIncident.advice, /Check the official/);
  assert.equal(JSON.stringify(publicIncident).includes(reporterDiscordId), false);
  assert.equal(JSON.stringify(publicIncident).includes('token=demo'), false);
  assert.equal(JSON.stringify(publicIncident).includes(input.description), false);
  assert.deepEqual(publicIncident.evidence, []);
  assert.deepEqual((await invoke(server, 'GET', '/v1/mvp/notifications/outbox', undefined, reviewers[0].token)).body.events, []);
});

test('two independent reviewers publish credible threats; duplicate and self approvals fail', async () => {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers });
  const server = createApiServer({ sentinel: createSentinel(store), mvp, reviewers, discordBotToken: botToken });
  const report = await mvp.submitDiscord({ description: 'A fictional suspicious wallet drain report.', evidence: [transactionEvidence] }, reporterDiscordId);
  const evidenceId = mvp.getReport(report.id, 'reviewer-a').evidence[0].id;
  assert.equal(mvp.listIncidents().length, 0);
  await assert.rejects(mvp.proposeFromReport(report.id, 'reviewer-a', {
    ...publicNarrative,
    level: 'credible_threat', severity: 'high', title: 'Fictional wallet drain warning',
    advice: 'Pause interactions with the fictional application and inspect official updates.',
    reason: 'A warning without a public source cannot be published.',
  }), { code: 'evidence_required' });
  const proposedResponse = await invoke(server, 'POST', `/v1/mvp/reports/${report.id}/publication`, {
    ...publicNarrative,
    level: 'credible_threat', severity: 'high', title: 'Fictional wallet drain warning',
    advice: 'Pause interactions with the fictional application and inspect official updates.',
    reason: 'Reviewers found sufficiently credible fictional evidence for a warning.',
    publicEvidenceIds: [evidenceId],
    reviewerId: 'lead',
  }, reviewers[0].token);
  assert.equal(proposedResponse.status, 200);
  const proposed = proposedResponse.body;
  assert.equal(proposed.status, 'pending');
  assert.equal(proposed.approvals[0].reviewerId, 'reviewer-a');
  assert.equal(proposed.requiredApprovals, 2);
  assert.equal(mvp.listIncidents().length, 0);
  assert.equal((await invoke(server, 'POST', `/v1/mvp/proposals/${proposed.id}/approval`, undefined, reviewers[0].token)).body.error, 'duplicate_approval');
  const approved = (await invoke(server, 'POST', `/v1/mvp/proposals/${proposed.id}/approval`, undefined, reviewers[1].token)).body;
  assert.equal(approved.status, 'published');
  assert.equal(approved.publishedIncident.id, 'SEN-0001');
  assert.deepEqual(approved.publishedIncident.evidence, [{ id: evidenceId, kind: 'transaction', reference: transactionEvidence.reference }]);
  assert.equal(mvp.listNotificationEvents('reviewer-a').length, 1);
  assert.equal(mvp.listNotificationEvents('reviewer-a')[0].deliveryState, 'draft');

  await assert.rejects(mvp.proposeFromIncident('SEN-0001', 'reviewer-a', {
    ...publicNarrative,
    level: 'under_investigation', severity: 'high', title: 'Fictional updated warning',
    advice: 'Click https://bad.example.test now to verify your wallet.',
    reason: 'A public action line must not embed a potentially dangerous URL.',
  }), { code: 'unsafe_public_text' });

  const own = await mvp.submitDiscord({ description: 'A reviewer-submitted fictional report.', evidence: [transactionEvidence] }, reviewers[0].discordId);
  const ownEvidenceId = mvp.getReport(own.id, 'reviewer-b').evidence[0].id;
  await assert.rejects(mvp.triage(own.id, 'reviewer-a', {}), { code: 'self_review' });
  await assert.rejects(mvp.proposeFromReport(own.id, 'reviewer-a', {
    ...publicNarrative,
    level: 'informational', title: 'Fictional reviewer-owned report',
    advice: 'Check the official project channels for additional information.',
    reason: 'A reviewer cannot publish their own submitted report.',
  }), { code: 'self_review' });
  const ownProposal = await mvp.proposeFromReport(own.id, 'reviewer-b', {
    ...publicNarrative,
    level: 'credible_threat', severity: 'medium', title: 'Fictional reviewer-owned report',
    advice: 'Check the official project channels for additional information.',
    reason: 'A different reviewer proposed this report for review.',
    publicEvidenceIds: [ownEvidenceId],
  });
  await assert.rejects(mvp.approveProposal(ownProposal.id, 'reviewer-a'), { code: 'self_review' });
});

test('public evidence requires explicit safe selection and cannot leak suspicious links or notes', async () => {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers });
  const report = await mvp.submitDiscord({
    description: 'A fictional report with both a dangerous link and a public notice.',
    targets: [{ kind: 'url', value: 'https://bad.example.test/claim?wallet=hidden' }],
    evidence: [
      { kind: 'link', reference: 'https://bad.example.test/claim?wallet=hidden', note: 'PRIVATE_REPORT_NOTE' },
      { kind: 'official_statement', reference: 'https://project.example.test/notice', note: 'PRIVATE_REPORT_NOTE' },
    ],
  }, reporterDiscordId);
  const [unsafe, safe] = mvp.getReport(report.id, 'reviewer-a').evidence;
  const input = {
    ...publicNarrative,
    level: 'credible_threat', severity: 'medium', title: 'Fictional claim site warning',
    advice: 'Do not connect a wallet to the suspicious link and check project updates.',
    reason: 'Reviewers must inspect the fictional official notice before publication.',
  };
  await assert.rejects(mvp.proposeFromReport(report.id, 'reviewer-a', { ...input, publicEvidenceIds: [unsafe.id] }), { code: 'unsafe_public_evidence' });
  const proposal = await mvp.proposeFromReport(report.id, 'reviewer-a', { ...input, publicEvidenceIds: [safe.id] });
  await mvp.approveProposal(proposal.id, 'reviewer-b');
  const publicJson = JSON.stringify(mvp.getIncident('SEN-0001'));
  assert.equal(publicJson.includes('bad.example.test'), false);
  assert.equal(publicJson.includes('PRIVATE_REPORT_NOTE'), false);
  assert.equal(publicJson.includes(reporterDiscordId), false);
  assert.match(publicJson, /project\.example\.test/);
});

test('under-investigation may open publicly with advice, while medium/low confirmed need two reviewers', async () => {
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers });
  const investigation = await mvp.submitDiscord({ description: 'A fictional lead with no supporting evidence yet.' }, reporterDiscordId);
  const opened = await mvp.proposeFromReport(investigation.id, 'reviewer-a', {
    ...publicNarrative,
    level: 'under_investigation', severity: 'medium', title: 'Fictional lead under review',
    advice: 'Pause any interaction with the claim and check official project updates.',
    reason: 'The lead is unconfirmed and is being checked by the review team.',
  });
  assert.equal(opened.status, 'published');
  assert.equal(opened.publishedIncident.level, 'under_investigation');
  assert.deepEqual(opened.publishedIncident.evidence, []);
  assert.deepEqual(mvp.listNotificationEvents('reviewer-a'), []);

  for (const severity of ['medium', 'low']) {
    const report = await mvp.submitDiscord({ description: `A fictional ${severity} confirmed case.`, evidence: [transactionEvidence] }, reporterDiscordId);
    const evidenceId = mvp.getReport(report.id, 'reviewer-a').evidence[0].id;
    const proposed = await mvp.proposeFromReport(report.id, 'reviewer-a', {
      ...publicNarrative,
      level: 'confirmed_incident', severity, title: `Fictional ${severity} confirmed case`,
      advice: 'Check the official updates and avoid the affected fictional application.',
      reason: 'Two reviewers manually inspected the fictional evidence for this case.',
      publicEvidenceIds: [evidenceId],
    });
    assert.equal(proposed.status, 'pending');
    assert.equal(proposed.leadRequired, false);
    const approved = await mvp.approveProposal(proposed.id, 'reviewer-b');
    assert.equal(approved.status, 'published');
  }
});

test('high confirmed incidents require Lead; the one-hour exception stays disabled without verified delivery', async () => {
  const store = await Store.open();
  let time = '2026-10-03T00:00:00.000Z';
  const mvp = createMvpService(store, { reviewers, now: () => time });
  const report = await mvp.submitDiscord({ description: 'Fictional critical incident requiring reviewers.', evidence: [transactionEvidence] }, reporterDiscordId);
  const evidenceId = mvp.getReport(report.id, 'reviewer-a').evidence[0].id;
  const proposed = await mvp.proposeFromReport(report.id, 'reviewer-a', {
    ...publicNarrative,
    level: 'confirmed_incident', severity: 'critical', title: 'Fictional critical incident',
    advice: 'Do not interact with the fictional app until official confirmation is available.',
    reason: 'Fictional evidence was reviewed for this quorum and Lead test.',
    publicEvidenceIds: [evidenceId],
  });
  assert.equal(proposed.leadRequired, true);
  time = '2026-10-03T01:01:00.000Z';
  const second = await mvp.approveProposal(proposed.id, 'reviewer-b');
  assert.equal(second.status, 'pending');
  assert.equal(mvp.listIncidents().length, 0);
  const lead = await mvp.approveProposal(proposed.id, 'lead');
  assert.equal(lead.status, 'published');
  assert.equal(lead.publishedIncident.id, 'SEN-0001');
  await assert.rejects(mvp.proposeFromIncident('SEN-0001', 'reviewer-a', {
    ...publicNarrative,
    level: 'false_alarm', severity: 'critical', title: 'Fictional false alarm',
    advice: 'This fictional alert is being reviewed again.', reason: 'This transition has no agreed approval rule yet.',
  }), { code: 'policy_unconfirmed' });
  const resolution = await mvp.proposeFromIncident('SEN-0001', 'reviewer-a', {
    ...publicNarrative,
    level: 'resolved', severity: 'critical', title: 'Fictional incident resolved',
    advice: 'Review the official project update before resuming activity.',
    reason: 'The fictional response completed and the team reviewed the outcome.',
  });
  assert.equal(resolution.leadRequired, true);
  assert.equal((await mvp.approveProposal(resolution.id, 'lead')).status, 'published');
  assert.equal(mvp.getIncident('SEN-0001').level, 'resolved');
});

test('pending proposal votes are pinned to the configured reviewer roster', async () => {
  const store = await Store.open();
  const original = createMvpService(store, { reviewers });
  const report = await original.submitDiscord({ description: 'A fictional report for roster migration.', evidence: [transactionEvidence] }, reporterDiscordId);
  const evidenceId = original.getReport(report.id, 'reviewer-a').evidence[0].id;
  const proposed = await original.proposeFromReport(report.id, 'reviewer-a', {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional roster review',
    advice: 'Check the project channels while reviewers investigate the claim.',
    reason: 'Fictional evidence was selected for the reviewer-roster change test.',
    publicEvidenceIds: [evidenceId],
  });
  const changedReviewers = reviewers.map((item) => item.id === 'reviewer-b' ? { ...item, discordId: '555555555555555555' } : item);
  const changed = createMvpService(store, { reviewers: changedReviewers });
  await assert.rejects(changed.approveProposal(proposed.id, 'reviewer-b'), { code: 'reviewer_roster_changed' });
  assert.equal(changed.listIncidents().length, 0);
  assert.throws(() => changed.cancelProposal(proposed.id, 'reviewer-b', { reason: 'Roster changed and this vote cannot count.' }), { code: 'lead_required' });
  const cancelled = await changed.cancelProposal(proposed.id, 'lead', { reason: 'Reviewer roster changed, so the old proposal must be replaced.' });
  assert.equal(cancelled.status, 'cancelled');
  const replacement = await changed.proposeFromReport(report.id, 'lead', {
    ...publicNarrative,
    level: 'credible_threat', severity: 'low', title: 'Fictional roster review',
    advice: 'Check the project channels while reviewers investigate the claim.',
    reason: 'Fictional evidence was re-evaluated under the current reviewer roster.',
    publicEvidenceIds: [evidenceId],
  });
  assert.equal((await changed.approveProposal(replacement.id, 'reviewer-b')).status, 'published');
});

test('MVP report and incident IDs are allocated atomically and persist beside legacy schema-1 data', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sentinel-mvp-'));
  try {
    const file = join(directory, 'state.json');
    const store = await Store.open(file);
    const mvp = createMvpService(store, { reviewers: [reviewers[0]] });
    const receipts = await Promise.all(Array.from({ length: 12 }, (_, index) =>
      mvp.submitDiscord({ description: `Fictional concurrent report number ${index + 1}.` }, reporterDiscordId)));
    assert.deepEqual(receipts.map((item) => item.id), Array.from({ length: 12 }, (_, index) => `R-${String(index + 1).padStart(4, '0')}`));
    const proposals = await Promise.all(receipts.map((item, index) => mvp.proposeFromReport(item.id, 'reviewer-a', {
      ...publicNarrative,
      level: 'informational', severity: null, title: `Fictional lead number ${index + 1}`,
      advice: 'Check official channels before interacting with any suspicious message.',
      reason: 'This fictional lead is published by the local single-reviewer demo.',
    })));
    assert.deepEqual(proposals.map((item) => item.publishedIncident.id), Array.from({ length: 12 }, (_, index) => `SEN-${String(index + 1).padStart(4, '0')}`));
    const restarted = createMvpService(await Store.open(file), { reviewers: [reviewers[0]] });
    assert.equal(restarted.listIncidents().length, 12);
    assert.equal(restarted.getIncident('SEN-0001').approvalMode, 'demo_single_reviewer');
    assert.equal((await restarted.submitDiscord({ description: 'Another fictional report after restart.' }, reporterDiscordId)).id, 'R-0013');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('MVP integration examples follow the trusted report and two-reviewer publication contract', async () => {
  const example = async (name) => JSON.parse(await readFile(new URL(`../examples/${name}.json`, import.meta.url), 'utf8'));
  const [input, privateExample, publication, publicExample] = await Promise.all([
    example('discord-report-request'), example('mvp-private-report'),
    example('mvp-publication-request'), example('mvp-incidents-response'),
  ]);
  const store = await Store.open();
  const mvp = createMvpService(store, { reviewers });
  const receipt = await mvp.submitDiscord(input, input.discordUserId);
  assert.equal(receipt.id, privateExample.id);
  const privateReport = mvp.getReport(receipt.id, 'reviewer-a');
  assert.equal(privateReport.targets[0].value, privateExample.targets[0].value);
  assert.equal(privateReport.evidence[0].reference, privateExample.evidence[0].reference);
  const proposal = await mvp.proposeFromReport(receipt.id, 'reviewer-a', {
    ...publication, publicEvidenceIds: [privateReport.evidence[0].id],
  });
  assert.equal(proposal.status, 'pending');
  await mvp.approveProposal(proposal.id, 'reviewer-b');
  const incident = mvp.getIncident('SEN-0001');
  assert.deepEqual(Object.keys(incident).sort(), Object.keys(publicExample.incidents[0]).sort());
  assert.equal(incident.level, publicExample.incidents[0].level);
  assert.equal(incident.title, publicExample.incidents[0].title);
  assert.equal(incident.evidence[0].reference, publicExample.incidents[0].evidence[0].reference);
  assert.equal(JSON.stringify(incident).includes(privateExample.targets[0].value), false);
});
