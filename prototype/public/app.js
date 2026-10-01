const byId = (id) => document.getElementById(id);
let selectedReportId = null;
let reports = [];
const classificationLabel = {
  informational: '信息线索', under_investigation: '调查中',
  credible_threat: '可信威胁', confirmed_incident: '已确认事件',
};

function node(tag, value, className) {
  const element = document.createElement(tag);
  if (value !== undefined) element.textContent = String(value);
  if (className) element.className = className;
  return element;
}

function showFeedback(id, message, error = false) {
  const element = byId(id);
  element.textContent = message;
  element.classList.toggle('error', error);
}

function time(value) {
  if (!value) return '未知';
  return `${new Date(value).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })} 北京时间`;
}

async function request(path, { method = 'GET', body, reviewer = false } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (reviewer) {
    const token = byId('reviewer-token').value.trim();
    if (!token) throw new Error('请先填写审核令牌');
    headers.authorization = `Bearer ${token}`;
  }
  const response = await fetch(path, {
    method, headers,
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.message || `请求失败 (${response.status})`);
  return result;
}

function evidenceList(items) {
  const list = node('ul');
  for (const item of items) {
    const row = node('li');
    row.append(node('span', `${item.kind === 'transaction' ? '交易' : '来源'}：`));
    if (item.kind === 'public_source') {
      const link = node('a', item.url);
      link.href = item.url;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      row.append(link);
    } else {
      row.append(node('code', item.txHash));
    }
    row.append(node('span', ` — ${item.note}`));
    list.append(row);
  }
  return list;
}

function alertCard(alert) {
  const card = node('article', undefined, 'card');
  const head = node('div', undefined, 'card-head');
  head.append(node('h3', alert.title), node('span', alert.status, `status ${alert.status}`));
  card.append(head, node('p', `链 ${alert.chainId} · 合约 ${alert.contractAddress}`));
  card.append(node('p', `公开级别：${classificationLabel[alert.classification] || alert.classification}`));
  card.append(node('p', `建议：${alert.advice}`));
  card.append(node('p', `发布：${time(alert.publishedAt)} · 版本 ${alert.version}`));
  card.append(node('p', `告警 ID：${alert.id}`));
  card.append(evidenceList(alert.evidence));
  if (alert.onchainObservation) {
    const observation = alert.onchainObservation;
    card.append(node('p', `最近链上观察：${time(observation.observedAt)}；${observation.findings.length} 笔交易证据。链上观察不代表恶意判断。`));
  }
  for (const correction of alert.corrections) {
    card.append(node('p', `更正 v${correction.version}（${time(correction.at)}）：${correction.reason}`));
  }
  if (alert.retraction) card.append(node('p', `撤回（${time(alert.retraction.at)}）：${alert.retraction.reason}`));
  return card;
}

async function refreshAlerts() {
  try {
    const [{ alerts }, history, summary] = await Promise.all([
      request('/v1/alerts'), request('/v1/alerts/history'), request('/v1/dashboard'),
    ]);
    const container = byId('alerts');
    container.replaceChildren(...(alerts.length ? alerts.map(alertCard) : [node('p', '目前没有公开告警。', 'empty')]));
    byId('alert-history').replaceChildren(...(history.alerts.length ? history.alerts.map(alertCard) : [node('p', '尚无已发布事件。', 'empty')]));
    byId('metric-active').textContent = summary.activeAlerts;
    byId('metric-credible').textContent = summary.credibleThreats;
    byId('metric-confirmed').textContent = summary.confirmedIncidents;
    byId('metric-retracted').textContent = summary.retractedAlerts;
  } catch (error) {
    byId('alerts').replaceChildren(node('p', error.message, 'empty'));
  }
}

function reportCard(report) {
  const button = node('button', undefined, 'card report-choice');
  button.type = 'button';
  const head = node('div', undefined, 'card-head');
  head.append(node('h3', report.title), node('span', report.status, `status ${report.status}`));
  button.append(head, node('p', `链 ${report.chainId} · ${report.contractAddress} · ${classificationLabel[report.classification] || '未分类'}`));
  button.addEventListener('click', () => selectReport(report.id));
  return button;
}

function selectReport(id) {
  selectedReportId = id;
  const report = reports.find((item) => item.id === id);
  const container = byId('selected-report');
  if (!report) {
    container.replaceChildren(node('p', '请选择报告。'));
    byId('review-actions').classList.add('hidden');
    return;
  }
  container.replaceChildren(
    node('strong', report.title),
    node('p', `状态：${report.status} · 级别：${classificationLabel[report.classification] || '未分类'} · 提交者：${report.reporterId}`),
    node('p', `链 ${report.chainId} · 合约 ${report.contractAddress}`),
    node('p', report.description),
    node('p', `证据 ${report.evidence.length} 条：`),
    evidenceList(report.evidence),
    node('p', `审核者：${report.reviewerId || '未分配'}`),
    node('p', `链上观察 ${report.observations?.length || 0} 次；事件记录 ${report.history.length} 条。`),
  );
  if (report.status === 'in_review') {
    const selection = node('div', undefined, 'evidence-selection');
    selection.append(node('strong', '选择可公开的证据（至少一条）'));
    for (const item of report.evidence) {
      const label = node('label');
      const checkbox = node('input');
      checkbox.type = 'checkbox';
      checkbox.name = 'publicEvidenceId';
      checkbox.value = item.id;
      label.append(checkbox, node('span', `${item.kind === 'transaction' ? '交易' : '来源'}：${item.kind === 'transaction' ? item.txHash : item.url}`));
      selection.append(label);
    }
    container.append(selection);
  }
  for (const observation of report.observations || []) {
    container.append(node('p', `链上检查 ${time(observation.observedAt)}：${observation.findings.map((finding) => `${finding.state} / 目标直接匹配 ${finding.directTargetMatch ?? '未知'}`).join('；') || '没有交易证据'}`));
  }
  for (const entry of report.history) {
    container.append(node('p', `${time(entry.at)} · ${entry.type}${entry.reason ? ` · ${entry.reason}` : ''}`));
  }
  byId('review-actions').classList.remove('hidden');
  byId('start-review').disabled = report.status !== 'submitted';
  byId('add-evidence').disabled = report.status !== 'in_review';
  byId('check-evidence').disabled = report.status !== 'in_review';
  byId('verify').disabled = report.status !== 'in_review';
  byId('reject').disabled = report.status !== 'in_review';
  byId('correct').disabled = report.status !== 'verified';
  byId('retract').disabled = report.status !== 'verified';
  if (report.status === 'verified') {
    byId('correction-title').value = report.alertVersions.at(-1).title;
    byId('correction-advice').value = report.alertVersions.at(-1).advice;
    byId('correction-classification').value = report.alertVersions.at(-1).classification || report.classification || 'credible_threat';
  }
}

async function refreshReports() {
  const result = await request('/v1/reports', { reviewer: true });
  reports = result.reports.slice().reverse();
  byId('reports').replaceChildren(...(reports.length ? reports.map(reportCard) : [node('p', '目前没有报告。', 'empty')]));
  selectReport(selectedReportId);
}

async function refreshContributors() {
  const { contributors } = await request('/v1/contributors', { reviewer: true });
  const cards = contributors.map((item) => {
    const card = node('div', undefined, 'card');
    card.append(node('strong', item.reporterId));
    card.append(node('p', `报告 ${item.reportCount} · 曾发布 ${item.verifiedCount} · 驳回 ${item.rejectedCount} · 待处理 ${item.pendingCount}`));
    return card;
  });
  byId('contributors').replaceChildren(...(cards.length ? cards : [node('p', '暂无贡献记录。', 'empty')]));
}

async function reviewerAction(path, body) {
  if (!selectedReportId) return showFeedback('review-feedback', '请先选择一份报告', true);
  try {
    await request(`/v1/reports/${selectedReportId}/${path}`, { method: 'POST', body, reviewer: true });
    showFeedback('review-feedback', '操作已保存');
    await refreshReports();
    await refreshAlerts();
    refreshOutbox().catch(() => {});
  } catch (error) {
    showFeedback('review-feedback', error.message, true);
  }
}

function watchTargetCard(target) {
  const card = node('article', undefined, 'card');
  const head = node('div', undefined, 'card-head');
  head.append(node('h3', target.label), node('span', target.active ? '监看中' : '已归档', `status ${target.active ? 'verified' : 'retracted'}`));
  card.append(head, node('p', `链 ${target.chainId} · ${target.address}`));
  const last = target.observations.at(-1);
  if (last) card.append(node('p', `最近观察：${time(last.observedAt)}，区块 ${last.fromBlock}–${last.toBlock}，${last.logCount} 条事件日志。`));
  if (target.archived) card.append(node('p', `归档理由：${target.archived.reason}`));
  if (target.active) {
    const check = node('button', '检查事件日志', 'button subtle');
    check.type = 'button';
    check.addEventListener('click', async () => {
      try {
        await request(`/v1/watchlist/${target.id}/check`, { method: 'POST', reviewer: true });
        showFeedback('watch-feedback', '只读检查已记录');
        await refreshWatchlist();
      } catch (error) { showFeedback('watch-feedback', error.message, true); }
    });
    const reason = node('textarea');
    reason.placeholder = '归档理由（至少 20 字符）';
    reason.maxLength = 1000;
    reason.rows = 2;
    const archive = node('button', '归档监看目标', 'button danger');
    archive.type = 'button';
    archive.addEventListener('click', async () => {
      try {
        await request(`/v1/watchlist/${target.id}/archive`, {
          method: 'POST', body: { reason: reason.value }, reviewer: true,
        });
        showFeedback('watch-feedback', '监看目标已归档');
        await refreshWatchlist();
      } catch (error) { showFeedback('watch-feedback', error.message, true); }
    });
    card.append(check, reason, archive);
  }
  return card;
}

async function refreshWatchlist() {
  const { targets } = await request('/v1/watchlist', { reviewer: true });
  byId('watchlist').replaceChildren(...(targets.length ? targets.map(watchTargetCard) : [node('p', '尚无监看地址。', 'empty')]));
}

async function refreshOutbox() {
  const { events } = await request('/v1/notifications/outbox', { reviewer: true });
  const cards = events.slice().reverse().map((event) => {
    const card = node('article', undefined, 'card');
    card.append(node('h3', `${event.kind} · ${classificationLabel[event.classification] || event.classification}`));
    card.append(node('p', event.title), node('p', event.advice));
    card.append(node('p', `告警 ${event.alertId} · v${event.version} · ${time(event.createdAt)} · 未发送`));
    return card;
  });
  byId('outbox').replaceChildren(...(cards.length ? cards : [node('p', '尚无通知草稿。', 'empty')]));
}

byId('fill-demo').addEventListener('click', () => {
  const form = byId('report-form');
  form.elements.reporterId.value = 'demo-community-member';
  form.elements.chainId.value = '10143';
  form.elements.contractAddress.value = '0x1111111111111111111111111111111111111111';
  form.elements.title.value = 'Demo: suspicious contract activity';
  form.elements.description.value = 'Fictional report for the local demonstration. No real contract is being accused.';
  form.elements.evidenceKind.value = 'transaction';
  form.elements.evidenceValue.value = `0x${'a'.repeat(64)}`;
  form.elements.evidenceNote.value = 'Fictional transaction hash for demonstrating the report workflow.';
});

byId('report-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const fields = Object.fromEntries(new FormData(event.currentTarget));
  const evidence = fields.evidenceKind === 'transaction'
    ? { kind: 'transaction', txHash: fields.evidenceValue, note: fields.evidenceNote }
    : { kind: 'public_source', url: fields.evidenceValue, note: fields.evidenceNote };
  try {
    const result = await request('/v1/reports', {
      method: 'POST',
      body: {
        reporterId: fields.reporterId,
        chainId: Number(fields.chainId),
        contractAddress: fields.contractAddress,
        title: fields.title,
        description: fields.description,
        evidence: [evidence],
      },
    });
    showFeedback('report-result', `已提交，报告 ID：${result.id}。当前不会公开。`);
    event.currentTarget.reset();
    if (byId('reviewer-token').value.trim()) {
      refreshReports().catch((error) => showFeedback('review-feedback', error.message, true));
      refreshContributors().catch(() => {});
    }
  } catch (error) {
    showFeedback('report-result', error.message, true);
  }
});

byId('refresh-alerts').addEventListener('click', refreshAlerts);
byId('lookup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const id = new FormData(event.currentTarget).get('alertId').trim();
  try {
    const alert = await request(`/v1/alerts/${encodeURIComponent(id)}`);
    byId('lookup-result').replaceChildren(alertCard(alert));
  } catch (error) {
    byId('lookup-result').replaceChildren(node('p', error.message, 'empty'));
  }
});
byId('load-reports').addEventListener('click', async () => {
  try {
    await Promise.all([refreshReports(), refreshContributors(), refreshWatchlist(), refreshOutbox()]);
    showFeedback('review-feedback', '报告队列已更新');
  } catch (error) {
    showFeedback('review-feedback', error.message, true);
  }
});
byId('load-watchlist').addEventListener('click', () => {
  refreshWatchlist().catch((error) => showFeedback('watch-feedback', error.message, true));
});
byId('load-outbox').addEventListener('click', () => {
  refreshOutbox().catch((error) => showFeedback('review-feedback', error.message, true));
});
byId('watch-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const fields = Object.fromEntries(new FormData(event.currentTarget));
  try {
    await request('/v1/watchlist', {
      method: 'POST', reviewer: true,
      body: { chainId: Number(fields.chainId), address: fields.address, label: fields.label },
    });
    showFeedback('watch-feedback', '已加入监看列表');
    event.currentTarget.reset();
    await refreshWatchlist();
  } catch (error) { showFeedback('watch-feedback', error.message, true); }
});
byId('start-review').addEventListener('click', () => reviewerAction('review'));
byId('add-evidence').addEventListener('click', () => {
  const kind = byId('added-evidence-kind').value;
  const value = byId('added-evidence-value').value;
  const note = byId('added-evidence-note').value;
  reviewerAction('evidence', kind === 'transaction'
    ? { kind, txHash: value, note }
    : { kind, url: value, note });
});
byId('check-evidence').addEventListener('click', () => reviewerAction('check-evidence'));
byId('verify').addEventListener('click', () => reviewerAction('decision', {
  outcome: 'verified', reason: byId('decision-reason').value, advice: byId('decision-advice').value,
  classification: byId('decision-classification').value,
  publicEvidenceIds: [...byId('selected-report').querySelectorAll('input[name="publicEvidenceId"]:checked')].map((input) => input.value),
}));
byId('reject').addEventListener('click', () => reviewerAction('decision', {
  outcome: 'rejected', reason: byId('decision-reason').value,
}));
byId('correct').addEventListener('click', () => reviewerAction('correction', {
  title: byId('correction-title').value,
  advice: byId('correction-advice').value,
  reason: byId('correction-reason').value,
  classification: byId('correction-classification').value,
}));
byId('retract').addEventListener('click', () => reviewerAction('retraction', {
  reason: byId('retraction-reason').value,
}));

selectReport(null);
refreshAlerts();
