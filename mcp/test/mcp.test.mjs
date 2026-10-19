import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';

const baseIncident = {
  target: { input: '', kind: 'domain', normalized: '' },
  matched: true,
  level: 'credible_threat',
  severity: 'high',
  advice: ['Do not connect your wallet.'],
  verifiedAt: '2026-10-06T01:30:00.000Z',
  incidentId: 'SEN-0002',
  incidentUrl: 'https://demo.test/mvp.html#SEN-0002',
  matchedIndicator: { kind: 'domain', value: 'velunor-claim.xyz', active: true },
  matches: [],
  checkedAt: '2026-10-19T14:47:27.743Z',
  disclaimer: 'Independent community project',
};

function responseFor(target) {
  const input = target ?? '';
  if (input === 'velunor-claim.xyz') {
    return { ...baseIncident, target: { input, kind: 'domain', normalized: input } };
  }
  if (input === 'cleared.example') {
    return { ...baseIncident, level: 'false_alarm', severity: 'critical', title: undefined, target: { input, kind: 'domain', normalized: input } };
  }
  if (input === 'resolved.example') {
    return { ...baseIncident, level: 'resolved', severity: 'high', target: { input, kind: 'domain', normalized: input } };
  }
  if (input === 'under.example') {
    return { ...baseIncident, level: 'under_investigation', severity: 'medium', target: { input, kind: 'domain', normalized: input } };
  }
  return {
    target: { input, kind: 'domain', normalized: input },
    matched: false,
    level: 'none',
    severity: null,
    advice: ['No published Sentinel incident matches this target.'],
    verifiedAt: null,
    incidentId: null,
    incidentUrl: null,
    matchedIndicator: null,
    matches: [],
    checkedAt: '2026-10-19T14:47:44.506Z',
    disclaimer: 'Independent community project',
  };
}

// Stub API. opts.dropFirst: destroy the socket on the first request (simulates
// the host's ~1-in-3 dropped new connections); opts.delayMs: stall responses.
function startStub({ dropFirst = false, delayMs = 0 } = {}) {
  let dropped = false;
  return new Promise((resolvePromise) => {
    const server = createServer((req, res) => {
      const target = new URL(req.url, 'http://x').searchParams.get('target') ?? '';
      if (dropFirst && !dropped) {
        dropped = true;
        req.socket.destroy();
        return;
      }
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(responseFor(target)));
      }, delayMs);
    });
    server.listen(0, '127.0.0.1', () => resolvePromise(server));
  });
}

function startMcp(stubPort, extraEnv = {}) {
  const child = spawn(process.execPath, [resolve(import.meta.dirname, '../src/index.mjs')], {
    env: { ...process.env, ...extraEnv, SENTINEL_CHECK_BASE_URL: `http://127.0.0.1:${stubPort}` },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const pending = [];
  const queue = [];
  const rl = createInterface(child.stdout);
  rl.on('line', (line) => {
    if (!line.trim()) return;
    const message = JSON.parse(line);
    if (pending.length) pending.shift()(message);
    else queue.push(message);
  });
  const next = () => new Promise((resolvePromise) => {
    if (queue.length) resolvePromise(queue.shift());
    else pending.push(resolvePromise);
  });
  const send = (message) => {
    child.stdin.write(`${JSON.stringify(message)}\n`);
  };
  const call = async (id, target) => {
    send({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'sentinel_check', arguments: { target } } });
    return next();
  };
  const stop = () => child.kill();
  return { child, next, send, call, stop };
}

async function initialize(mcp) {
  mcp.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
    protocolVersion: '2025-06-18', capabilities: {},
    clientInfo: { name: 'test-client', version: '0.0.1' },
  } });
  const init = await mcp.next();
  assert.equal(init.id, 1);
  assert.equal(init.result.serverInfo.name, 'sentinel_check');
  mcp.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
}

test('tool description and core results carry the safety rules', async () => {
  const stub = await startStub();
  const mcp = startMcp(stub.address().port);
  try {
    await initialize(mcp);

    mcp.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = await mcp.next();
    const tool = tools.result.tools.find((item) => item.name === 'sentinel_check');
    assert.ok(tool, 'sentinel_check tool must be listed');
    // Ollie 2026-10-19 + 2026-10-20: description must carry every safety rule.
    assert.match(tool.description, /credible_threat/);
    assert.match(tool.description, /confirmed_incident/);
    assert.match(tool.description, /STOP/);
    assert.match(tool.description, /ask a human/);
    assert.match(tool.description, /under_investigation.*pause and ask a human/s);
    assert.match(tool.description, /resolved.*NOT an endorsement/s);
    assert.match(tool.description, /false_alarm.*NOT an endorsement/s);
    assert.match(tool.description, /UNKNOWN/);

    const hit = await mcp.call(3, 'velunor-claim.xyz');
    assert.equal(hit.result.isError, undefined);
    const hitText = hit.result.content[0].text;
    assert.match(hitText, /credible_threat/);
    assert.match(hitText, /SEN-0002/);
    assert.match(hitText, /STOP/);
    assert.match(hitText, /ask a human/);

    const miss = await mcp.call(4, 'example-notlisted.org');
    const missText = miss.result.content[0].text;
    assert.match(missText, /UNKNOWN/);
    assert.match(missText, /not as safe|NOT as safe/);

    const investigating = await mcp.call(5, 'under.example');
    const investigatingText = investigating.result.content[0].text;
    assert.match(investigatingText, /under_investigation/);
    assert.match(investigatingText, /PAUSE AND ASK A HUMAN/);

    const cleared = await mcp.call(6, 'cleared.example');
    assert.match(cleared.result.content[0].text, /NOT an endorsement/);

    const resolved = await mcp.call(7, 'resolved.example');
    assert.match(resolved.result.content[0].text, /NOT an endorsement/);
  } finally {
    mcp.stop();
    stub.close();
  }
});

test('one quick retry recovers a dropped connection', async () => {
  const stub = await startStub({ dropFirst: true });
  const mcp = startMcp(stub.address().port);
  try {
    await initialize(mcp);
    // First connection is destroyed by the stub; the tool must still answer.
    const hit = await mcp.call(2, 'velunor-claim.xyz');
    assert.equal(hit.result.isError, undefined);
    assert.match(hit.result.content[0].text, /SEN-0002/);
  } finally {
    mcp.stop();
    stub.close();
  }
});

test('timeout reports the configured limit and stays fail-safe', async () => {
  const stub = await startStub({ delayMs: 500 });
  const mcp = startMcp(stub.address().port, { SENTINEL_CHECK_TIMEOUT_MS: '100' });
  try {
    await initialize(mcp);
    const failure = await mcp.call(2, 'velunor-claim.xyz');
    assert.equal(failure.result.isError, true);
    const text = failure.result.content[0].text;
    assert.match(text, /timed out after 100 ms/);
    assert.match(text, /UNKNOWN/);
  } finally {
    mcp.stop();
    stub.close();
  }
});

test('upstream connection failure returns isError with fail-safe text', async () => {
  // Port 1: nothing listens there, connection refused fails fast.
  const mcp = startMcp(1);
  try {
    await initialize(mcp);
    const failure = await mcp.call(2, 'velunor-claim.xyz');
    assert.equal(failure.result.isError, true);
    const text = failure.result.content[0].text;
    assert.match(text, /network or upstream failure/);
    assert.match(text, /UNKNOWN/);
  } finally {
    mcp.stop();
  }
});
