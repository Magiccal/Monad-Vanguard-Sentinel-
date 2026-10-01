# Backend verification and evidence demo

This Node.js 20 backend is a working prototype for the team's incident and verification layer. It demonstrates one case: a community report about a suspicious contract. Reports stay private until a reviewer makes a manual publication decision. Read-only Monad RPC checks provide transaction facts; they do not determine whether a contract is malicious.

The team interface draft is in [`openapi.json`](openapi.json), with ready-to-use fictional payloads in [`examples/`](examples/README.md). The proposed repository boundaries are documented in [`docs/architecture.md`](../docs/architecture.md), and the current review flow is in [`docs/verification.md`](../docs/verification.md).

## Run locally

No package installation is needed.

```bash
cd backend
npm test
npm run demo
export REVIEWER_ID=demo-reviewer
export REVIEWER_TOKEN="$(openssl rand -hex 32)"
npm start
```

Open `http://127.0.0.1:8787/` for the local demo page. The page uses fictional addresses and transaction hashes; it is not the team frontend. The API listens only on loopback. Set `PORT` to change the port and `DATA_FILE` to change the JSON data path. The default is `backend/data/sentinel.json` when started from the backend directory. Keep the token and data file private; `data/` is ignored by Git.

Set `RPC_URL` to an HTTPS Monad RPC endpoint before starting the server to enable read-only transaction and watchlist checks. The report's chain ID must match the RPC chain ID. The RPC provider receives queried transaction hashes. No transaction is sent onchain.

## Implemented flow

```text
submitted / informational
  → in_review / under_investigation
  → verified / credible_threat or confirmed_incident
  → corrected → retracted
  ↘ rejected (never public)
```

- A report contains a chain ID, contract address, title, description, reporter label, and one to ten transaction hashes or public HTTPS sources.
- The assigned reviewer can add evidence and record a decision with a reason. Publication also requires action advice and explicit `publicEvidenceIds`; only selected evidence appears in public alerts.
- Reporter and evidence contributor identities remain in reviewer responses. Unselected evidence and its onchain observations remain private.
- Published alerts have history, corrections, and retractions. Publication, correction, and retraction create local notification drafts; no Telegram, Discord, or user delivery occurs.
- A reviewer can manually inspect transaction receipts and logs from watchlisted addresses. The first watch check covers the latest 100 blocks; later checks resume after the saved block, advancing at most 500 blocks per request. Repeated logs are deduplicated by block hash and log index. These observations never assign a risk verdict.
- Contributor counts use self-declared reporter labels. They are not identity verification or a reputation score.

## Integration endpoints

| Method and path | Use |
| --- | --- |
| `POST /v1/reports` | Community report submission |
| `GET /v1/alerts`, `GET /v1/alerts/history`, `GET /v1/alerts/:id` | Public alerts and history |
| `GET /v1/dashboard` | Public alert counts |
| `GET /v1/reports`, `GET /v1/reports/:id` | Reviewer queue and report details |
| `POST /v1/reports/:id/review`, `/evidence`, `/check-evidence`, `/decision`, `/correction`, `/retraction` | Reviewer workflow |
| `GET /v1/watchlist`, `POST /v1/watchlist`, `POST /v1/watchlist/:id/check`, `/archive` | Manual watchlist with a saved scan cursor |
| `GET /v1/notifications/outbox` | Unsent events for future bot integration |

Reviewer routes require `Authorization: Bearer <REVIEWER_TOKEN>`. The reviewer identity comes from `REVIEWER_ID`, not from the request. The browser page keeps its entered token only in page memory.

To publish a verified report, `POST /v1/reports/:id/decision` requires `outcome`, `classification`, `reason`, `advice`, and `publicEvidenceIds`. The evidence IDs come from the reviewer report response. See [`openapi.json`](openapi.json) for all request and response shapes.

## Limits before deployment

The shared token, self-declared reporter label, single-process JSON store, and loopback listener are for a local demo. Production authentication, storage, rate limiting, source credibility rules, notification delivery, and any onchain write design remain team decisions. Watch scans are manual and do not reconcile chain reorganizations. A successful transaction, matching target address, or manual `verified` status is not a guarantee that a contract is safe.
