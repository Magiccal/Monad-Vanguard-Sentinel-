import test from 'node:test';
import assert from 'node:assert/strict';
import { createRpcClient, inspectTransactionEvidence, inspectWatchTarget } from '../src/rpc.mjs';

const txHash = `0x${'a'.repeat(64)}`;
const address = '0x1111111111111111111111111111111111111111';
const report = {
  chainId: 10143,
  contractAddress: address,
  evidence: [{ id: 'evidence-1', kind: 'transaction', txHash }],
};

test('RPC observations distinguish chain facts from a risk verdict', async () => {
  const calls = [];
  const rpc = {
    async call(method) {
      calls.push(method);
      if (method === 'eth_chainId') return `0x${report.chainId.toString(16)}`;
      if (method === 'eth_getTransactionByHash') return { hash: txHash, to: address };
      if (method === 'eth_getTransactionReceipt') return {
        transactionHash: txHash, blockNumber: '0x123', status: '0x1',
      };
      throw new Error(`Unexpected RPC method: ${method}`);
    },
  };
  const result = await inspectTransactionEvidence(report, rpc, { now: () => '2026-09-28T12:00:00.000Z' });
  assert.deepEqual(calls, ['eth_chainId', 'eth_getTransactionByHash', 'eth_getTransactionReceipt']);
  assert.deepEqual(result.findings, [{
    evidenceId: 'evidence-1', txHash, state: 'mined', directTargetMatch: true,
    txTo: address, blockNumber: '0x123', receiptStatus: 'success',
  }]);
  assert.equal('verified' in result, false);
});

test('RPC chain mismatch stops inspection before transaction lookup', async () => {
  let calls = 0;
  const rpc = { async call() { calls++; return '0x1'; } };
  await assert.rejects(inspectTransactionEvidence(report, rpc), { code: 'rpc_chain_mismatch' });
  assert.equal(calls, 1);
});

test('transaction absent from RPC is recorded as not found', async () => {
  const rpc = {
    async call(method) {
      return method === 'eth_chainId' ? `0x${report.chainId.toString(16)}` : null;
    },
  };
  const result = await inspectTransactionEvidence(report, rpc);
  assert.equal(result.findings[0].state, 'not_found');
  assert.equal(result.findings[0].directTargetMatch, null);
});

test('RPC endpoint is server-configured and must use HTTPS or loopback', () => {
  assert.throws(() => createRpcClient('http://example.org/rpc'), /HTTPS/);
  assert.throws(() => createRpcClient('https://user:secret@example.org/rpc'), /credentials/);
  assert.ok(createRpcClient('https://example.org/rpc'));
  assert.ok(createRpcClient('http://127.0.0.1:8545'));
});

test('watchlist check records recent emitted logs without assigning risk', async () => {
  const methods = [];
  const rpc = {
    async call(method, params) {
      methods.push([method, params]);
      if (method === 'eth_chainId') return '0x279f';
      if (method === 'eth_blockNumber') return '0x100';
      if (method === 'eth_getLogs') return [{
        address, transactionHash: txHash, blockNumber: '0xff',
        blockHash: `0x${'c'.repeat(64)}`, logIndex: '0x1', topics: [`0x${'b'.repeat(64)}`],
      }];
      throw new Error(`Unexpected RPC method: ${method}`);
    },
  };
  const result = await inspectWatchTarget({ chainId: 10143, address }, rpc);
  assert.equal(result.logCount, 1);
  assert.equal(result.state, 'scanned');
  assert.equal(result.fromBlock, '0x9d');
  assert.equal(result.samples[0].txHash, txHash);
  assert.equal(methods[2][1][0].toBlock, '0x100');
  assert.equal('risk' in result, false);
});

test('watchlist resumes from its saved cursor, chunks long gaps, and deduplicates logs', async () => {
  const filters = [];
  let latest = '0x305';
  const repeatedLog = {
    address, transactionHash: txHash, blockNumber: '0x101',
    blockHash: `0x${'c'.repeat(64)}`, logIndex: '0x1', topics: [],
  };
  const rpc = {
    async call(method, params) {
      if (method === 'eth_chainId') return '0x279f';
      if (method === 'eth_blockNumber') return latest;
      if (method === 'eth_getLogs') {
        filters.push(params[0]);
        return params[0].fromBlock === '0x101' ? [repeatedLog, repeatedLog] : [];
      }
      throw new Error(`Unexpected RPC method: ${method}`);
    },
  };
  const first = await inspectWatchTarget({ chainId: 10143, address, lastScannedBlock: '0x100' }, rpc);
  assert.equal(first.fromBlock, '0x101');
  assert.equal(first.toBlock, '0x2f4');
  assert.equal(first.hasMore, true);
  assert.equal(first.logCount, 1);
  assert.equal(first.duplicateCount, 1);
  assert.equal(filters.length, 5);
  assert.equal(filters.at(-1).toBlock, '0x2f4');

  const second = await inspectWatchTarget({
    chainId: 10143, address, lastScannedBlock: first.toBlock, recentLogKeys: first.logKeys,
  }, rpc);
  assert.equal(second.fromBlock, '0x2f5');
  assert.equal(second.toBlock, latest);
  assert.equal(second.hasMore, false);
  assert.equal(second.logCount, 0);

  const count = filters.length;
  latest = '0x305';
  const third = await inspectWatchTarget({ chainId: 10143, address, lastScannedBlock: second.toBlock }, rpc);
  assert.equal(third.state, 'up_to_date');
  assert.equal(filters.length, count);
});

test('watchlist rejects RPC logs outside the requested block range', async () => {
  const rpc = {
    async call(method) {
      if (method === 'eth_chainId') return '0x279f';
      if (method === 'eth_blockNumber') return '0x100';
      return [{
        address, transactionHash: txHash, blockNumber: '0x1',
        blockHash: `0x${'c'.repeat(64)}`, logIndex: '0x1', topics: [],
      }];
    },
  };
  await assert.rejects(inspectWatchTarget({ chainId: 10143, address }, rpc), { code: 'rpc_error' });
});
