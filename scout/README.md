# Envio Scout (v1)

Onchain watch agent that files leads into the Sentinel review queue as the
registered `envio-scout` agent. **It never publishes** — everything files as
`submitted` and humans decide everything.

## Scope (Ollie-approved plan, 2026-10-21)

- **Event 1 — lookalike deployments**: new Monad testnet contract creations
  whose name/symbol impersonates a watchlisted brand.
- **Event 2 — honeypot-style controls**: bytecode contains selectors of known
  drainer control functions (blacklists, bot lists, trading toggles, tax
  setters, limit removers).
- A report is filed **only when both signals agree** on the same contract, and
  the creation transaction is cited as the evidence reference.
- **Event 3 (phishing pages) is out of v1** — it would require web scraping,
  not onchain data. Revisit later if a trusted source appears.
- Descriptions always say "possible impersonation … not a confirmed verdict"
  because reviewers may copy that text into public incidents.

## Safety switches

| Switch | Mechanism | Effect |
| --- | --- | --- |
| `DRY_RUN` (env, **default `true`**) | `DRY_RUN=false` to file for real | Dry run appends the full payload it *would* file to `scout-dry-run.log` and sends nothing. |
| Kill switch | `scout-paused.flag` next to the state file (path via `SCOUT_KILL_FILE`) | If the file exists the scout pauses immediately — no filing, checked every cycle and again before any send. `touch` to stop, remove to resume. No redeploy needed. |
| Rate caps | self-capped at 3 filings / rolling 24h, ≥2h spacing | Logged candidates that hit the cap are recorded in state but not sent. |
| Per-filing log | console line | `FILED status=201 report=R-#### contract=0x… signals=impersonation+honeypot(...) brand=…` — never logs the token. |

## Configuration (env)

| Variable | Default | Purpose |
| --- | --- | --- |
| `MONAD_RPC_URL` | `https://testnet-rpc.monad.xyz` | JSON-RPC endpoint to scan. |
| `SENTINEL_BASE_URL` | `https://sentinel-security-demo.app.workbuddy.host` | Backend base for intake. |
| `SENTINEL_TOKEN` | — | **Required in real mode** (the `envio-scout` agent token; keep secret). Not needed for dry run. |
| `DRY_RUN` | `true` | `false` to actually file. |
| `POLL_SECONDS` | `60` | Cycle interval (min 5). |
| `SCOUT_STATE_FILE` | `./scout-state.json` | Cursor, seen contracts, filing log. |
| `SCOUT_KILL_FILE` | `./scout-paused.flag` | Kill-switch path. |
| `SCOUT_DRY_RUN_LOG` | `./scout-dry-run.log` | Dry-run payload log. |
| `SCOUT_WATCHLIST_FILE` | `./impersonation-watchlist.json` | Brand list (JSON array of lowercase strings). |
| `SCOUT_MAX_PER_24H` / `SCOUT_MIN_SPACING_H` | `3` / `2` | Self-caps. |
| `SCOUT_MAX_BLOCKS_PER_CYCLE` | `400` | Blocks processed per cycle. Monad testnet produces ~3.7 blocks/s (~220 per 60s cycle), so 400 keeps up with margin. |
| `SCOUT_BLOCK_BATCH_SIZE` | `50` | JSON-RPC batch size for `eth_getBlockReceipts` (one POST per batch, ~25 blocks/s measured). Falls back to per-block receipts, then the classic full-block scan. |
| `SCOUT_LAG_JUMP_BLOCKS` / `SCOUT_LAG_JUMP_TAIL` | `800` / `10` | Only after real downtime: if the cursor falls more than 800 blocks behind (normal drift never triggers), skip the gap and resume at latest−10. **Every skipped range is logged and kept in state (`stats.skippedRanges`), so gaps are auditable.** |
| `SCOUT_RECEIPTS_WINDOW` | `30` | Never scan past latest−N: the public RPC only serves `eth_getBlockReceipts` for a recent window (measured: nulls start at ~300 blocks behind the tip), so blocks outside it are deferred, never silently marked scanned. Any unexpected null receipt is counted in `stats.receiptUnavailable` and logged. |

Deployment detection: the scout prefers `eth_getBlockReceipts` (one call per
block, catches both direct creations and factory deployments); it falls back
to the classic `tx.to === null` full-block scan if the RPC doesn't support it.

Auth goes through the public domain with the `x-sentinel-token` fallback
header (the hosted-proxy workaround) — exactly the production path, and every
such authentication is logged by the backend (`agent-fallback-auth`) without
the token.

## Run

Dry run (default — no token needed):

```bash
mkdir -p ~/.workbuddy/sentinel-local/scout && cd ~/.workbuddy/sentinel-local/scout
SCOUT_STATE_FILE="$PWD/scout-state.json" SCOUT_KILL_FILE="$PWD/scout-paused.flag" \
SCOUT_DRY_RUN_LOG="$PWD/scout-dry-run.log" SCOUT_WATCHLIST_FILE="$PWD/impersonation-watchlist.json" \
node ~/Documents/hackson/reviewer-flow-work/scout/envio-scout.mjs
```

Real mode (after the dry-run review):

```bash
DRY_RUN=false SENTINEL_TOKEN="$(cat ~/.workbuddy/sentinel-local/agent-envio-scout.token)" \
… same env as above … node …/scout/envio-scout.mjs
```

Stop immediately: `touch ~/.workbuddy/sentinel-local/scout/scout-paused.flag`.

## Dry-run report (what we review before real mode)

The day's report to the Lead draws on two artifacts:

- `scout-state.json` → `stats`: `contractsSeen` (token-like contracts checked),
  `impersonationOnly` (weak — lookalike name but no drainer controls, **not
  filed**), `bothSignals` (strong flags that would have been filed),
  `skippedRanges` (blocks not scanned due to lag jumps).
- `scout-dry-run.log` → one `IMPERSONATION-ONLY` line per weak match (address,
  brand, symbol/name, tx) plus the **full payload** for every strong flag —
  example payloads come straight from here.

Genuine-vs-noise judgement is made by a human over these entries; the scout
never files the weak ones.

## Honest scope notes

- v1 reads the same onchain data directly via the Monad testnet RPC; pointing
  it at an Envio HyperIndex endpoint later is a configuration swap, not a
  rewrite.
- Signal B uses bytecode selector matching — a coarse heuristic. That is why
  both signals must agree and why wording stays hedged; reviewers judge every
  lead.
- The scout dedupes against contracts it has already seen and its own filed
  list; the backend enforces the 10/h flood cap, the 20-open cap, and the
  reputation ratio rule regardless.
