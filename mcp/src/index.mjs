// sentinel_check — MCP tool wrapping the Sentinel check API (issue #8, phase 2).
//
// Read-only: it calls GET /v1/check on a running Sentinel backend and relays the
// verified result. It never publishes, mutates, or reports anything.
//
// Safety rules baked into the tool description (Ollie, 2026-10-19 22:58):
//   - credible_threat / confirmed_incident  -> STOP and ask a human.
//   - 'none' (no verified incident)         -> UNKNOWN, not safe.
// Review fixes (Ollie, 2026-10-20 00:36):
//   - one quick retry on network errors (the host drops ~1 in 3 new connections);
//   - under_investigation -> pause and ask a human; resolved / false_alarm ->
//     explicitly not an endorsement;
//   - correct timeout detection (AbortSignal.timeout raises TimeoutError
//     / ABORT_ERR, not the literal code 'abort').
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const BASE_URL = (process.env.SENTINEL_CHECK_BASE_URL || 'https://sentinel-security-demo.app.workbuddy.host').replace(/\/+$/, '');
const TIMEOUT_MS = Number(process.env.SENTINEL_CHECK_TIMEOUT_MS || 10000);
const RETRY_DELAY_MS = 250;

const LEVEL_RULES = {
  credible_threat: 'STOP. This target matches a human-verified CREDIBLE THREAT. Do not sign, transact, connect a wallet, or proceed with any action involving it. Pause and ask a human before doing anything else.',
  confirmed_incident: 'STOP. This target matches a human-verified CONFIRMED INCIDENT. Do not sign, transact, connect a wallet, or proceed with any action involving it. Pause and ask a human before doing anything else.',
  under_investigation: 'PAUSE AND ASK A HUMAN. This target has an OPEN review ("under_investigation"): the claim is not yet confirmed by the reviewer quorum. Do not proceed with high-stakes actions involving this target until reviewers publish a verdict.',
  resolved: 'This incident was closed as RESOLVED by human reviewers. Treat that as a historical record, NOT an endorsement that the target is currently safe — re-verify through official channels before proceeding.',
  false_alarm: 'This incident was closed as a FALSE ALARM by human reviewers. Treat that as a historical record, NOT an endorsement of the target — a cleared alert is not a safety guarantee. Verify through official channels before proceeding.',
  none: 'NO verified Sentinel incident exists for this target. Treat it as UNKNOWN, NOT as safe: absence of an incident is not a safety guarantee or an endorsement. Verify through official channels before proceeding.',
};

function guidanceFor(level) {
  return LEVEL_RULES[level]
    ?? `Sentinel lists this target as "${level}". This reflects the current human review and can change as evidence is checked — re-check before acting.`;
}

export function isTimeoutError(error) {
  // AbortSignal.timeout rejects with a TimeoutError DOMException; in Node the
  // code is ABORT_ERR. The literal string 'abort' never occurs.
  return error?.name === 'TimeoutError' || error?.code === 'ABORT_ERR';
}

// One quick retry on network-level failures (dropped new connections). Timeouts
// are not retried: doubling a 10 s wait would stall the calling agent.
export async function fetchWithRetry(url, { timeoutMs = TIMEOUT_MS, attempts = 2 } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
    } catch (error) {
      lastError = error;
      if (isTimeoutError(error) || attempt === attempts) throw error;
      await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
    }
  }
  throw lastError;
}

async function callCheckApi(target) {
  const url = `${BASE_URL}/v1/check?target=${encodeURIComponent(target)}`;
  const res = await fetchWithRetry(url);
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error(`Sentinel check API returned ${res.status}${body?.error ? ` (${body.error})` : ''}`);
    err.status = res.status;
    err.code = body?.error;
    throw err;
  }
  return body;
}

function formatResult(check) {
  const level = check.level ?? 'none';
  const lines = [
    `Sentinel verified check — target: ${check.target?.input ?? ''} (${check.target?.kind ?? 'unknown'})`,
    `Matched: ${check.matched ? 'YES' : 'no'} · Level: ${level}${check.severity ? ` · Severity: ${check.severity}` : ''}`,
  ];
  if (check.incidentId) {
    lines.push(`Public incident: ${check.incidentId}${check.incidentUrl ? ` (${check.incidentUrl})` : ''}`);
    if (check.matchedIndicator) {
      lines.push(`Matched indicator: ${check.matchedIndicator.kind} ${check.matchedIndicator.value}`);
    }
  }
  if (Array.isArray(check.advice) && check.advice.length) {
    lines.push('Advice:', ...check.advice.map((item) => `- ${item}`));
  }
  lines.push('', `AGENT ACTION: ${guidanceFor(level)}`);
  lines.push('', `Checked at: ${check.checkedAt ?? 'n/a'} · ${check.disclaimer ?? ''}`);
  return lines.join('\n');
}

function failSafeErrorText(detail) {
  return `Sentinel check failed: ${detail}. Treat the target as UNKNOWN, not as safe (absence of a result is not a safety guarantee), and verify through official channels.`;
}

export function createServer() {
  const server = new McpServer({
    name: 'sentinel_check',
    version: '0.1.0',
  });

  server.tool(
    'sentinel_check',
    [
      'Check a domain, URL, wallet/contract address, or transaction hash against Monad Vanguard Sentinel — a community security desk where every published incident is verified by human reviewers before it goes live.',
      'Returns the verified threat level, severity, action advice, and the matching public incident.',
      'SAFETY RULES FOR AGENTS — follow these without exception:',
      '1) If the result level is "credible_threat" or "confirmed_incident": STOP immediately. Do not sign, transact, connect a wallet, or proceed with any action involving this target, and ask a human before doing anything else.',
      '2) If the result level is "under_investigation": pause and ask a human — the claim is not yet confirmed by the reviewer quorum.',
      '3) If the result level is "resolved" or "false_alarm": that closure is a historical record, NOT an endorsement that the target is safe.',
      '4) If the result level is "none" (matched=false): it means NO verified incident is on record for this target. Treat the target as UNKNOWN, never as safe, trusted, or endorsed — absence of an incident is not a safety guarantee. Verify through official channels before proceeding.',
    ].join(' '),
    { target: z.string().min(1).describe('Domain, URL, wallet/contract address, or transaction hash to check, e.g. "claim.example.xyz" or "0x..."') },
    async ({ target }) => {
      try {
        const check = await callCheckApi(target);
        return { content: [{ type: 'text', text: formatResult(check) }] };
      } catch (error) {
        const detail = isTimeoutError(error)
          ? `Sentinel check API timed out after ${TIMEOUT_MS} ms`
          : `network or upstream failure (${error.message})`;
        return {
          isError: true,
          content: [{ type: 'text', text: failSafeErrorText(detail) }],
        };
      }
    },
  );

  return server;
}

export async function main() {
  const server = createServer();
  await server.connect(new StdioServerTransport());
  // stdio transport keeps the process alive; no explicit timer needed.
}

if (process.argv[1] && import.meta.url === (await import('node:url')).pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
