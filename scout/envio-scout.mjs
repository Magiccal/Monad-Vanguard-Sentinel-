#!/usr/bin/env node
// Envio Scout — onchain watch for the Sentinel review queue (issue #8).
//
// v1 scope (Ollie-approved plan 2026-10-21 04:58, with his four tweaks):
//   - Watches ONLY onchain signals (events 1 & 2). The phishing-page signal
//     (event 3) would have required web scraping and is out of v1.
//   - DRY_RUN mode (default ON): every report it would file is written to the
//     dry-run log instead of being sent. Run ~a day, review the flag rate,
//     then flip to real mode.
//   - Kill switch: if the kill file exists, the scout stops filing instantly
//     (checked every cycle and again immediately before any send).
//   - Every real filing is logged with report ID, contract address, and the
//     two signals that matched. Never logs the agent token.
//   - Descriptions say "possible impersonation" — never a verdict — because
//     reviewers may copy that text into public incidents.
//
// Event 1 — lookalike deployments: new contract creations whose name/symbol
//   impersonates a watchlisted brand.
// Event 2 — honeypot-style function patterns: bytecode contains selectors of
//   known drainer controls (blacklists, bot lists, trading toggles, tax
//   setters, limit removers).
// A report is filed only when BOTH signals agree on the same contract and a
// transaction (creation tx) can be cited. Everything files as `submitted` —
// the scout never publishes; humans decide everything.
//
// Rate: self-capped at 3 filings per rolling 24h with >= 2h spacing (the
// backend's own 10/h flood cap and 20-open cap are respected implicitly, and
// enforced server-side regardless).
//
// v1 reads onchain data via the Monad testnet RPC directly — the same
// signals an Envio HyperIndex deployment would expose; pointing it at an
// Envio indexer endpoint later is a configuration swap, not a rewrite.

import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';

const M64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const ROTC = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

function rotl(v, n) {
  return ((v << n) | (v >> (64n - n))) & M64;
}

function keccakF(a) {
  const C = new Array(5).fill(0n);
  const D = new Array(5).fill(0n);
  const B = new Array(25).fill(0n);
  for (let round = 0; round < 24; round += 1) {
    // theta
    for (let x = 0; x < 5; x += 1) C[x] = (a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]) & M64;
    for (let x = 0; x < 5; x += 1) D[x] = (C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1n)) & M64;
    for (let x = 0; x < 5; x += 1) for (let y = 0; y < 25; y += 5) a[x + y] = (a[x + y] ^ D[x]) & M64;
    // rho + pi (flat index = x + 5*y; ROTC holds r[x][y])
    for (let x = 0; x < 5; x += 1) {
      for (let y = 0; y < 5; y += 1) {
        const from = x + 5 * y;
        const to = y + 5 * ((2 * x + 3 * y) % 5);
        B[to] = rotl(a[from], BigInt(ROTC[from]));
      }
    }
    // chi
    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x += 1) {
        a[x + y] = (B[x + y] ^ (~B[((x + 1) % 5) + y] & B[((x + 2) % 5) + y])) & M64;
      }
    }
    // iota
    a[0] = (a[0] ^ RC[round]) & M64;
  }
}

function keccak256(bytes) {
  const rate = 136;
  const state = new Array(25).fill(0n);
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  padded.set(bytes);
  padded[bytes.length] ^= 0x01;
  padded[padded.length - 1] ^= 0x80;
  for (let off = 0; off < padded.length; off += rate) {
    for (let lane = 0; lane < rate; lane += 8) {
      const index = lane / 8;
      for (let j = 0; j < 8; j += 1) state[index] ^= BigInt(padded[off + lane + j]) << BigInt(8 * j);
      state[index] &= M64;
    }
    keccakF(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 8) {
    for (let j = 0; j < 8; j += 1) out[i + j] = Number((state[i / 8] >> BigInt(8 * j)) & 0xffn);
  }
  return out;
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Known-good digests: if these fail the build is wrong — refuse to run.
const selfTest = toHex(keccak256(Buffer.from('transfer(address,uint256)')));
if (selfTest !== 'a9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b') {
  console.error(`[scout] keccak256 self-test FAILED (${selfTest}) — refusing to run`);
  process.exit(1);
}

const ENV = process.env;
const RPC_URL = ENV.MONAD_RPC_URL || 'https://testnet-rpc.monad.xyz';
const BASE_URL = (ENV.SENTINEL_BASE_URL || 'https://sentinel-security-demo.app.workbuddy.host').replace(/\/$/, '');
const TOKEN = ENV.SENTINEL_TOKEN || '';
const DRY_RUN = (ENV.DRY_RUN ?? 'true') !== 'false';
const POLL_SECONDS = Number(ENV.POLL_SECONDS || 60);
const STATE_FILE = resolve(ENV.SCOUT_STATE_FILE || 'scout-state.json');
const KILL_FILE = resolve(ENV.SCOUT_KILL_FILE || 'scout-paused.flag');
const DRY_RUN_LOG = resolve(ENV.SCOUT_DRY_RUN_LOG || 'scout-dry-run.log');
const WATCHLIST_FILE = resolve(ENV.SCOUT_WATCHLIST_FILE || 'impersonation-watchlist.json');
const MAX_PER_24H = Number(ENV.SCOUT_MAX_PER_24H || 3);
const MIN_SPACING_MS = Number(ENV.SCOUT_MIN_SPACING_H || 2) * 3600_000;
const MAX_BLOCKS_PER_CYCLE = Number(ENV.SCOUT_MAX_BLOCKS_PER_CYCLE || 300);
const BLOCK_BATCH_SIZE = Number(ENV.SCOUT_BLOCK_BATCH_SIZE || 50);
const LAG_JUMP_BLOCKS = Number(ENV.SCOUT_LAG_JUMP_BLOCKS || 200);
const LAG_JUMP_TAIL = Number(ENV.SCOUT_LAG_JUMP_TAIL || 10);
const START_BLOCKS_BACK = Number(ENV.SCOUT_START_BLOCKS_BACK || 30);

const DEFAULT_WATCHLIST = ['usdc', 'usdt', 'tether', 'monad', 'envio', 'binance', 'coinbase', 'uniswap', 'metamask', 'opensea', 'aave', 'pendle'];
let watchlist = DEFAULT_WATCHLIST;
if (existsSync(WATCHLIST_FILE)) {
  try { watchlist = JSON.parse(readFileSync(WATCHLIST_FILE, 'utf8')); } catch { /* keep defaults */ }
}

// Honeypot-style control functions whose presence in bytecode is signal B.
// Selectors are computed from signatures with the (self-tested) keccak256.
const HONEYPOT_SIGNATURES = [
  'setBlacklist(address,bool)', 'addBlacklist(address)', 'blacklist(address,bool)',
  'setBots(address[],bool)', 'setBot(address,bool)', 'addBot(address)',
  'setTradingEnabled(bool)', 'enableTrading(bool)', 'setTrading(bool)',
  'removeLimits()', 'setLimits(uint256,uint256)', 'setMaxTxAmount(uint256)',
  'setTaxes(uint256,uint256,uint256)', 'setSellTax(uint256)', 'setBuyTax(uint256)',
  'setFees(uint256,uint256,uint256)', 'setCooldownEnabled(bool)', 'setAntibot(address,bool)',
];
const HONEYPOT_SELECTORS = HONEYPOT_SIGNATURES.map((sig) => toHex(keccak256(Buffer.from(sig))).slice(0, 8));

const SELECTOR = {
  name: '06fdde03',
  symbol: '95d89b41',
};

let state = {
  cursorBlock: null,
  seen: {},
  filings: [],
  // Running totals for the dry-run report Ollie asked for: how many
  // contracts were checked, how many were impersonation-only (weak), and
  // how many hit BOTH signals (strong flags).
  stats: { contractsSeen: 0, impersonationOnly: 0, bothSignals: 0, skippedRanges: [] },
  startedAt: new Date().toISOString(),
};
if (existsSync(STATE_FILE)) {
  try { state = { ...state, ...JSON.parse(readFileSync(STATE_FILE, 'utf8')) }; } catch { /* fresh state */ }
}

function saveState() {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function log(message) {
  console.log(`[scout ${new Date().toISOString()}] ${message}`);
}

async function postRpc(payload) {
  const response = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return response.json();
}

async function jsonRpc(method, params) {
  const body = await postRpc({ jsonrpc: '2.0', id: 1, method, params });
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

function normalize(value) {
  return String(value || '').toLowerCase().replace(/[^a-z0-9]+/g, '');
}

// Signal A: watchlist impersonation on symbol or name. Returns the brand.
function impersonationMatch(symbol, name) {
  for (const [value, label] of [[normalize(symbol), `symbol "${symbol}"`], [normalize(name), `name "${name}"`]]) {
    if (!value) continue;
    for (const brand of watchlist) {
      if (value === brand || (brand.length >= 4 && value.includes(brand))) {
        return { brand, where: label };
      }
    }
  }
  return null;
}

// Signal B: bytecode contains any honeypot-style control selector.
function honeypotMatch(code) {
  const hit = HONEYPOT_SELECTORS.find((selector) => code.includes(selector));
  return hit ? HONEYPOT_SIGNATURES[HONEYPOT_SELECTORS.indexOf(hit)] : null;
}

async function readContractString(address, selector, label) {
  try {
    const data = await jsonRpc('eth_call', [{ to: address, data: `0x${selector}` }, 'latest']);
    if (!data || data === '0x' || data.length < 130) return null;
    const length = parseInt(data.slice(66, 130), 16);
    if (!Number.isFinite(length) || length <= 0 || length > 256) return null;
    return Buffer.from(data.slice(130, 130 + length * 2), 'hex').toString('utf8').replace(/\0+$/, '');
  } catch {
    return null; // not a token-like contract, or call reverted
  }
}

function killSwitchPresent() {
  return existsSync(KILL_FILE);
}

// Monad testnet produces blocks far faster than one-RPC-call-per-block can
// scan (measured ~3.7 blocks/s), so the default path batches many
// eth_getBlockReceipts calls into a single JSON-RPC batch POST — one round
// trip per ~50 blocks (measured ~25 blocks/s, comfortably ahead of the
// chain). Fallbacks: per-block receipts, then the classic full-block scan.
async function fetchCreations(startBlock, target) {
  if (BLOCK_BATCH_SIZE > 1) {
    try {
      const creations = [];
      for (let from = startBlock; from <= target; from += BLOCK_BATCH_SIZE) {
        const to = Math.min(target, from + BLOCK_BATCH_SIZE - 1);
        const batch = [];
        for (let b = from; b <= to; b += 1) {
          batch.push({ jsonrpc: '2.0', id: b - from, method: 'eth_getBlockReceipts', params: [`0x${b.toString(16)}`] });
        }
        const body = await postRpc(batch);
        if (!Array.isArray(body) || body.length !== batch.length) throw new Error('RPC rejected JSON-RPC batch');
        for (const entry of body) {
          const receipts = entry?.result;
          if (!Array.isArray(receipts)) continue; // null result = block has no receipts yet
          for (const r of receipts) {
            if (r.contractAddress && r.transactionHash) creations.push({ txHash: r.transactionHash, address: r.contractAddress });
          }
        }
      }
      return creations;
    } catch { /* fall through to per-block */ }
  }
  try {
    const creations = [];
    for (let block = startBlock; block <= target; block += 1) {
      const receipts = await jsonRpc('eth_getBlockReceipts', [`0x${block.toString(16)}`]);
      if (Array.isArray(receipts)) {
        for (const r of receipts) {
          if (r.contractAddress && r.transactionHash) creations.push({ txHash: r.transactionHash, address: r.contractAddress });
        }
      }
    }
    return creations;
  } catch { /* fall through to classic scan */ }
  const creations = [];
  for (let block = startBlock; block <= target; block += 1) {
    const blockData = await jsonRpc('eth_getBlockByNumber', [`0x${block.toString(16)}`, true]);
    if (blockData && Array.isArray(blockData.transactions)) {
      for (const tx of blockData.transactions) {
        if (tx.to !== null || !tx.hash) continue; // direct contract creations only
        const receipt = await jsonRpc('eth_getTransactionReceipt', [tx.hash]);
        if (receipt?.contractAddress) creations.push({ txHash: tx.hash, address: receipt.contractAddress });
      }
    }
  }
  return creations;
}

function rateCapStatus(now = Date.now()) {
  const recent = state.filings.filter((f) => now - Date.parse(f.at) < 24 * 3600_000);
  const spacingOk = state.filings.length === 0 || now - Date.parse(state.filings[state.filings.length - 1].at) >= MIN_SPACING_MS;
  return { count: recent.length, spacingOk, allowed: spacingOk && recent.length < MAX_PER_24H };
}

function buildPayload(candidate) {
  return {
    description:
      `Possible impersonation of ${candidate.brand}: token "${candidate.symbol}" (name "${candidate.name}") ` +
      `deployed on Monad testnet at contract ${candidate.address} in transaction ${candidate.txHash}. ` +
      `Signals: (1) watchlist name match on the ${candidate.matchWhere}; (2) honeypot-style control function ` +
      `"${candidate.honeypotFn}" present in the bytecode. Filed as an automated lead for human review — ` +
      `this is a possible impersonation, not a confirmed verdict.`,
    targets: [{ kind: 'address', value: candidate.address }],
    evidence: [{ kind: 'transaction', reference: candidate.txHash, note: 'Contract creation transaction observed on Monad testnet.' }],
    incidentType: 'malicious_contract',
  };
}

async function fileReport(candidate) {
  const payload = buildPayload(candidate);
  if (DRY_RUN) {
    const line = `${new Date().toISOString()} DRY-RUN would file for contract ${candidate.address} (brand ${candidate.brand}, signals: impersonation + honeypot "${candidate.honeypotFn}")\n${JSON.stringify(payload, null, 2)}\n---\n`;
    appendFileSync(DRY_RUN_LOG, line);
    log(`DRY-RUN: would file for ${candidate.address} (brand ${candidate.brand}); payload appended to ${DRY_RUN_LOG}`);
    return { dryRun: true };
  }
  const response = await fetch(`${BASE_URL}/v1/agents/reports`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-sentinel-token': TOKEN },
    body: JSON.stringify(payload),
  });
  const body = await response.json().catch(() => ({}));
  // Ollie's ask: log every filing with report ID, contract, and the signals.
  log(`FILED status=${response.status} report=${body.id ?? '?'} contract=${candidate.address} signals=impersonation+honeypot(${candidate.honeypotFn}) brand=${candidate.brand}`);
  if (response.status !== 201) {
    log(`filing failed: ${JSON.stringify(body).slice(0, 300)}`);
    return { ok: false };
  }
  return { ok: true, reportId: body.id };
}

async function scanCycle() {
  const latest = Number(await jsonRpc('eth_blockNumber', []));
  if (state.cursorBlock === null) {
    state.cursorBlock = latest - START_BLOCKS_BACK;
    log(`first cycle: starting from block ${state.cursorBlock} (latest ${latest})`);
  }
  // Near-real-time watch, not historical backfill: if we ever fall too far
  // behind (downtime, RPC slowness), skip the gap instead of drowning in it.
  // Ollie's ask: always log WHICH blocks were skipped, not just that a jump
  // happened, so the gap is auditable later.
  if (latest - state.cursorBlock > LAG_JUMP_BLOCKS) {
    const skippedFrom = state.cursorBlock + 1;
    const skippedTo = latest - LAG_JUMP_TAIL;
    log(`lag detected: cursor ${state.cursorBlock} is >${LAG_JUMP_BLOCKS} blocks behind latest ${latest} — SKIPPING blocks ${skippedFrom}..${skippedTo} (${skippedTo - skippedFrom + 1} blocks not scanned), resuming at ${skippedTo + 1}`);
    state.stats.skippedRanges.push({ from: skippedFrom, to: skippedTo, blocks: skippedTo - skippedFrom + 1, at: new Date().toISOString() });
    state.stats.skippedRanges = state.stats.skippedRanges.slice(-50);
    state.cursorBlock = skippedTo;
    saveState();
  }
  const startBlock = state.cursorBlock + 1;
  const target = Math.min(latest, state.cursorBlock + MAX_BLOCKS_PER_CYCLE);
  let candidates = 0;
  const creations = await fetchCreations(startBlock, target);
  for (const { txHash, address } of creations) {
      if (state.seen[address]) continue;
      state.seen[address] = txHash;
      state.stats.contractsSeen += 1;
      const [symbol, name] = await Promise.all([
        readContractString(address, SELECTOR.symbol, 'symbol'),
        readContractString(address, SELECTOR.name, 'name'),
      ]);
      if (!symbol && !name) continue;
      const impersonation = impersonationMatch(symbol, name);
      if (!impersonation) continue; // signal A gate first — cheap on candidates
      const code = await jsonRpc('eth_getCode', [address, 'latest']);
      const honeypotFn = honeypotMatch(code);
      if (!honeypotFn) {
        // Weak signal (impersonation name only). Recorded — not filed — so the
        // dry-run report can separate strong flags from lookalike noise.
        state.stats.impersonationOnly += 1;
        const line = `${new Date().toISOString()} IMPERSONATION-ONLY (not filed, needs both signals) contract ${address} brand=${impersonation.brand} match=${impersonation.where} symbol="${symbol || ''}" name="${name || ''}" tx=${txHash}\n`;
        appendFileSync(DRY_RUN_LOG, line);
        log(`impersonation-only match skipped (needs both signals): ${address} symbol="${symbol}" brand=${impersonation.brand} (recorded to ${DRY_RUN_LOG})`);
        continue;
      }
      candidates += 1;
      state.stats.bothSignals += 1;
      const rate = rateCapStatus();
      const candidate = { address, txHash, symbol: symbol || '(empty)', name: name || '(empty)', ...impersonation, honeypotFn };
      if (killSwitchPresent()) {
        log(`kill switch present — candidate ${address} logged but not filed`);
        state.filings.push({ at: new Date().toISOString(), address, blockedBy: 'kill_switch' });
      } else if (!rate.allowed) {
        log(`rate cap (${rate.count}/${MAX_PER_24H} in 24h, spacingOk=${rate.spacingOk}) — candidate ${address} logged but not filed`);
        state.filings.push({ at: new Date().toISOString(), address, blockedBy: 'rate_cap' });
      } else {
        const result = await fileReport(candidate);
        if (result.ok || result.dryRun) {
          state.filings.push({ at: new Date().toISOString(), address, reportId: result.reportId ?? null, dryRun: Boolean(result.dryRun) });
        }
      }
  }
  state.cursorBlock = target;
  saveState();
  log(`cycle done: blocks ${startBlock}..${target} scanned, ${candidates} candidate(s), ${Object.keys(state.seen).length} contracts seen`);
}

function pruneState() {
  const cutoff = Date.now() - 7 * 24 * 3600_000;
  const seen = Object.fromEntries(Object.entries(state.seen).filter(([, hash], index) => index < 5000));
  state.seen = seen;
  state.filings = state.filings.filter((f) => Date.parse(f.at) > cutoff);
}

async function main() {
  log(`envio-scout starting: dryRun=${DRY_RUN} rpc=${RPC_URL} base=${BASE_URL} poll=${POLL_SECONDS}s killFile=${KILL_FILE}`);
  log(`watchlist: ${watchlist.join(', ')}`);
  if (!DRY_RUN && !TOKEN) {
    console.error('[scout] real mode requires SENTINEL_TOKEN — refusing to start');
    process.exit(1);
  }
  mkdirSync(resolve(STATE_FILE, '..'), { recursive: true });
  const seconds = Number.isFinite(POLL_SECONDS) && POLL_SECONDS >= 5 ? POLL_SECONDS : 60;
  for (;;) {
    try {
      if (killSwitchPresent()) {
        log(`kill switch present (${KILL_FILE}) — scout paused; remove the file to resume`);
      } else {
        pruneState();
        await scanCycle();
      }
    } catch (error) {
      log(`cycle error: ${error.message?.slice(0, 300)}`);
    }
    await new Promise((r) => setTimeout(r, seconds * 1000));
  }
}

main().catch((error) => {
  console.error(`[scout] fatal: ${error.stack || error.message}`);
  process.exit(1);
});
