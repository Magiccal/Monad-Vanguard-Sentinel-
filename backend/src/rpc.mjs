import { DomainError } from './core.mjs';

function rpcError(code, message) {
  throw new DomainError(502, code, message);
}

export function createRpcClient(endpoint, { fetchImpl = fetch, timeoutMs = 5000 } = {}) {
  let url;
  try { url = new URL(endpoint); } catch { throw new Error('RPC_URL must be a valid URL'); }
  const localHttp = url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !localHttp) || url.username || url.password) {
    throw new Error('RPC_URL must use HTTPS, or HTTP on loopback, without URL credentials');
  }

  let nextId = 0;
  return {
    async call(method, params = []) {
      const id = ++nextId;
      let response;
      try {
        response = await fetchImpl(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'error',
        });
      } catch {
        rpcError('rpc_unavailable', 'RPC request failed or timed out');
      }
      if (!response.ok) rpcError('rpc_unavailable', `RPC returned HTTP ${response.status}`);
      let payload;
      try {
        const body = await response.text();
        if (body.length > 1024 * 1024) rpcError('rpc_error', 'RPC response is too large');
        payload = JSON.parse(body);
      } catch (error) {
        if (error instanceof DomainError) throw error;
        rpcError('rpc_error', 'RPC returned invalid JSON');
      }
      if (!payload || typeof payload !== 'object' || Array.isArray(payload) ||
          payload.jsonrpc !== '2.0' || payload.id !== id || payload.error || !('result' in payload)) {
        rpcError('rpc_error', 'RPC returned an invalid response');
      }
      return payload.result;
    },
  };
}

async function assertChain(expectedChainId, rpc) {
  const chainIdHex = await rpc.call('eth_chainId');
  if (typeof chainIdHex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(chainIdHex)) {
    rpcError('rpc_error', 'RPC returned an invalid chain ID');
  }
  const rpcChainId = Number.parseInt(chainIdHex, 16);
  if (!Number.isSafeInteger(rpcChainId) || rpcChainId !== expectedChainId) {
    rpcError('rpc_chain_mismatch', 'RPC chain ID differs from report chain ID');
  }
  return rpcChainId;
}

export async function inspectTransactionEvidence(report, rpc, { now = () => new Date().toISOString() } = {}) {
  const rpcChainId = await assertChain(report.chainId, rpc);

  const findings = [];
  for (const item of report.evidence.filter(({ kind }) => kind === 'transaction')) {
    const tx = await rpc.call('eth_getTransactionByHash', [item.txHash]);
    if (tx === null) {
      findings.push({ evidenceId: item.id, txHash: item.txHash, state: 'not_found', directTargetMatch: null });
      continue;
    }
    if (!tx || typeof tx.hash !== 'string' || tx.hash.toLowerCase() !== item.txHash ||
        (tx.to !== null && (typeof tx.to !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(tx.to)))) {
      rpcError('rpc_error', 'RPC returned an invalid transaction');
    }
    const directTargetMatch = tx.to?.toLowerCase() === report.contractAddress;
    const receipt = await rpc.call('eth_getTransactionReceipt', [item.txHash]);
    if (receipt === null) {
      findings.push({
        evidenceId: item.id, txHash: item.txHash, state: 'pending',
        directTargetMatch, txTo: tx.to?.toLowerCase() ?? null,
      });
      continue;
    }
    if (!receipt || typeof receipt.transactionHash !== 'string' ||
        receipt.transactionHash.toLowerCase() !== item.txHash ||
        typeof receipt.blockNumber !== 'string' || !/^0x[0-9a-fA-F]+$/.test(receipt.blockNumber)) {
      rpcError('rpc_error', 'RPC returned an invalid transaction receipt');
    }
    findings.push({
      evidenceId: item.id, txHash: item.txHash, state: 'mined',
      directTargetMatch, txTo: tx.to?.toLowerCase() ?? null,
      blockNumber: receipt.blockNumber,
      receiptStatus: receipt.status === '0x1' ? 'success' : receipt.status === '0x0' ? 'failure' : 'unknown',
    });
  }
  return { observedAt: now(), chainId: rpcChainId, findings };
}

export async function inspectWatchTarget(target, rpc, {
  now = () => new Date().toISOString(), lookback = 100, maxBlocksPerCheck = 500, chunkSize = 100,
} = {}) {
  if (!Number.isSafeInteger(lookback) || lookback < 1 || lookback > 1000 ||
      !Number.isSafeInteger(maxBlocksPerCheck) || maxBlocksPerCheck < 1 || maxBlocksPerCheck > 2000 ||
      !Number.isSafeInteger(chunkSize) || chunkSize < 1 || chunkSize > 1000) {
    throw new Error('Invalid watch scan range');
  }
  const chainId = await assertChain(target.chainId, rpc);
  const latestHex = await rpc.call('eth_blockNumber');
  if (typeof latestHex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(latestHex)) {
    rpcError('rpc_error', 'RPC returned an invalid block number');
  }
  const latest = BigInt(latestHex);
  const previousBlock = target.lastScannedBlock ?? target.observations?.at(-1)?.toBlock ?? null;
  if (previousBlock !== null && (typeof previousBlock !== 'string' || !/^0x[0-9a-fA-F]+$/.test(previousBlock))) {
    rpcError('rpc_error', 'Stored watch cursor is invalid');
  }
  const previous = previousBlock === null ? null : BigInt(previousBlock);
  if (previous !== null && previous >= latest) {
    return {
      state: 'up_to_date', observedAt: now(), chainId, previousBlock,
      fromBlock: null, toBlock: previousBlock, latestBlock: latestHex,
      hasMore: false, logCount: 0, duplicateCount: 0, samples: [],
    };
  }

  const from = previous === null
    ? (latest >= BigInt(lookback - 1) ? latest - BigInt(lookback - 1) : 0n)
    : previous + 1n;
  const to = from + BigInt(maxBlocksPerCheck - 1) < latest ? from + BigInt(maxBlocksPerCheck - 1) : latest;
  const seen = new Set(target.recentLogKeys ?? []);
  const logKeys = [];
  const samples = [];
  let duplicateCount = 0;
  for (let start = from; start <= to; start += BigInt(chunkSize)) {
    const end = start + BigInt(chunkSize - 1) < to ? start + BigInt(chunkSize - 1) : to;
    const logs = await rpc.call('eth_getLogs', [{
      address: target.address,
      fromBlock: `0x${start.toString(16)}`,
      toBlock: `0x${end.toString(16)}`,
    }]);
    if (!Array.isArray(logs) || logs.length > 1000) rpcError('rpc_error', 'RPC returned invalid or excessive logs');
    for (const log of logs) {
      if (!log || typeof log !== 'object' || typeof log.address !== 'string' ||
          log.address.toLowerCase() !== target.address ||
          typeof log.transactionHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(log.transactionHash) ||
          typeof log.blockHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(log.blockHash) ||
          typeof log.logIndex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(log.logIndex) ||
          typeof log.blockNumber !== 'string' || !/^0x[0-9a-fA-F]+$/.test(log.blockNumber) ||
          BigInt(log.blockNumber) < start || BigInt(log.blockNumber) > end) {
        rpcError('rpc_error', 'RPC returned an invalid log');
      }
      if (log.removed === true) rpcError('rpc_error', 'RPC returned a removed log; retry the check');
      const key = `${log.blockHash.toLowerCase()}:${BigInt(log.logIndex).toString(16)}`;
      if (seen.has(key)) {
        duplicateCount++;
        continue;
      }
      seen.add(key);
      logKeys.push(key);
      if (samples.length < 20) samples.push({
        txHash: log.transactionHash.toLowerCase(), blockNumber: log.blockNumber,
        blockHash: log.blockHash.toLowerCase(), logIndex: log.logIndex,
        topic0: typeof log.topics?.[0] === 'string' ? log.topics[0] : null,
      });
    }
  }
  return {
    state: 'scanned', observedAt: now(), chainId, previousBlock,
    fromBlock: `0x${from.toString(16)}`, toBlock: `0x${to.toString(16)}`,
    latestBlock: latestHex, hasMore: to < latest,
    logCount: logKeys.length, duplicateCount, samples, logKeys,
  };
}
