import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';

const matchedResponse = {
  target: { input: 'velunor-claim.xyz', kind: 'domain', normalized: 'velunor-claim.xyz' },
  matched: true,
  level: 'credible_threat',
  severity: 'high',
  advice: ['Do not connect your wallet to velunor-claim[.]xyz.'],
  verifiedAt: '2026-10-06T01:30:00.000Z',
  incidentId: 'SEN-0002',
  incidentUrl: 'https://demo.test/mvp.html#SEN-0002',
  matchedIndicator: { kind: 'domain', value: 'velunor-claim.xyz', active: true },
  matches: [],
  checkedAt: '2026-10-19T14:47:27.743Z',
  disclaimer: 'Independent community project',
};

const noneResponse = {
  target: { input: 'example-notlisted.org', kind: 'domain', normalized: 'example-notlisted.org' },
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

function startStub() {
  return new Promise((resolvePromise) => {
    const server = createServer((req, res) => {
      const target = new URL(req.url, 'http://x').searchParams.get('target') ?? '';
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(target === 'velunor-claim.xyz' ? matchedResponse : noneResponse));
    });
    server.listen(0, '127.0.0.1', () => resolvePromise(server));
  });
}

function startMcp(stubPort) {
  const child = spawn(process.execPath, [resolve(import.meta.dirname, '../src/index.mjs')], {
    env: { ...process.env, SENTINEL_CHECK_BASE_URL: `http://127.0.0.1:${stubPort}` },
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
  return { child, next, send };
}

test('sentinel_check MCP server: initialize, describe, and safety-first results', async () => {
  const stub = await startStub();
  const mcp = startMcp(stub.address().port);
  try {
    mcp.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2025-06-18', capabilities: {},
      clientInfo: { name: 'test-client', version: '0.0.1' },
    } });
    const init = await mcp.next();
    assert.equal(init.id, 1);
    assert.equal(init.result.serverInfo.name, 'sentinel_check');
    mcp.send({ jsonrpc: '2.0', method: 'notifications/initialized' });

    mcp.send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = await mcp.next();
    assert.equal(tools.id, 2);
    const tool = tools.result.tools.find((item) => item.name === 'sentinel_check');
    assert.ok(tool, 'sentinel_check tool must be listed');
    // Ollie 2026-10-19: the description must carry both safety rules.
    assert.match(tool.description, /credible_threat/);
    assert.match(tool.description, /confirmed_incident/);
    assert.match(tool.description, /STOP/);
    assert.match(tool.description, /ask a human/);
    assert.match(tool.description, /UNKNOWN/);
    assert.match(tool.description, /not.*safe/s);

    // Matched credible threat -> STOP instruction surfaces in the output.
    mcp.send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: {
      name: 'sentinel_check', arguments: { target: 'velunor-claim.xyz' },
    } });
    const hit = await mcp.next();
    assert.equal(hit.id, 3);
    assert.equal(hit.result.isError, undefined);
    const hitText = hit.result.content[0].text;
    assert.match(hitText, /credible_threat/);
    assert.match(hitText, /SEN-0002/);
    assert.match(hitText, /STOP/);
    assert.match(hitText, /ask a human/);

    // 'none' result -> explicit UNKNOWN, not safe wording.
    mcp.send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: {
      name: 'sentinel_check', arguments: { target: 'example-notlisted.org' },
    } });
    const miss = await mcp.next();
    assert.equal(miss.id, 4);
    const missText = miss.result.content[0].text;
    assert.match(missText, /UNKNOWN/);
    assert.match(missText, /not as safe|NOT as safe/);

    // API failure -> isError + fail-safe guidance (port 1 = connection refused).
    const failing = startMcp(1);
    try {
      failing.send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
        protocolVersion: '2025-06-18', capabilities: {},
        clientInfo: { name: 'test-client', version: '0.0.1' },
      } });
      await failing.next();
      failing.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
      failing.send({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: {
        name: 'sentinel_check', arguments: { target: 'velunor-claim.xyz' },
      } });
      const failure = await failing.next();
      assert.equal(failure.id, 5);
      assert.equal(failure.result.isError, true);
      assert.match(failure.result.content[0].text, /UNKNOWN/);
    } finally {
      failing.child.kill();
    }
  } finally {
    mcp.child.kill();
    stub.close();
  }
});
