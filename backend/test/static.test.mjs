import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { createApiServer } from '../src/server.mjs';
import { createSentinel } from '../src/core.mjs';
import { Store } from '../src/store.mjs';

test('local demo page and assets are served with a restrictive content policy', async () => {
  const sentinel = createSentinel(await Store.open());
  const server = createApiServer({
    sentinel, reviewerToken: 'fictional-test-reviewer-token-12345', reviewerId: 'reviewer',
  });
  const invoke = (url) => new Promise((resolve) => {
    const req = Readable.from([]);
    Object.assign(req, { method: 'GET', url, headers: {} });
    const res = {
      headersSent: false,
      writeHead(status, headers) { this.status = status; this.headers = headers; this.headersSent = true; },
      end(body) { resolve({ status: this.status, headers: this.headers, body: body.toString() }); },
    };
    server.emit('request', req, res);
  });

  const page = await invoke('/');
  assert.equal(page.status, 200);
  assert.match(page.headers['content-type'], /text\/html/);
  assert.match(page.headers['content-security-policy'], /script-src 'self'/);
  assert.match(page.body, /提交线索/);
  assert.match(page.body, /Not affiliated with Monad Foundation/);
  assert.match(page.body, /\/app\.js/);
  assert.equal((await invoke('/app.js')).status, 200);
  assert.equal((await invoke('/styles.css')).status, 200);
  const contract = await invoke('/openapi.json');
  assert.equal(contract.status, 200);
  assert.equal(JSON.parse(contract.body).openapi, '3.1.0');
});
