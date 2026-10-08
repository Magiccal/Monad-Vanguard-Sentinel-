# Backend MVP workflow and legacy evidence demo

This Node.js 20 backend now contains **two deliberately separate modes**. The new Discord MVP API is in [`mvp-openapi.json`](mvp-openapi.json). The older suspicious-contract demo and browser UI are in [`openapi.json`](openapi.json); they are disabled with HTTP 410 whenever the MVP mode is configured. Frontend and bot integrations should use the **MVP contract**, never the legacy `/v1/reports` or `/v1/alerts` contract.

The proposed repository boundaries are documented in [`docs/architecture.md`](../docs/architecture.md), and the review flow is in [`docs/verification.md`](../docs/verification.md). Fictional example payloads are in [`examples/`](examples/README.md).

## Discord MVP mode

Enable this mode with a server-side `DISCORD_BOT_TOKEN` and configured reviewer Discord IDs. This is a **trusted bot adapter contract**: the bot authenticates with its own bearer token and asserts a `discordUserId` taken from the Discord interaction. This backend does not itself verify Discord interaction signatures or user OAuth sessions. Never put the bot token in a browser. Direct web submission must wait for a trusted user-authentication adapter.

For a **local single-reviewer demo** with fictional Discord IDs:

```bash
cd backend
export REVIEWER_ID=demo-reviewer
export REVIEWER_DISCORD_ID=111111111111111111
export REVIEWER_TOKEN="$(openssl rand -hex 32)"
export DISCORD_BOT_TOKEN="$(openssl rand -hex 32)"
npm start
```

Run `npm run demo:mvp` for a self-contained, fictional 3-reviewer quorum walkthrough that does not start the HTTP server or send messages.

For the agreed 3-reviewer approval model, configure `REVIEWERS_JSON` as a server-side JSON array of **three distinct** `{ "id", "discordId", "token", "isLead" }` records, with exactly one `isLead: true`. Each token must be at least 24 characters and distinct from the bot token; keep all tokens secret. Do not populate the array from incoming request bodies. A single reviewer is marked `demo_single_reviewer` in every published incident and is **not** the production approval policy.

MVP endpoints:

| Method and path | Use |
| --- | --- |
| `POST /v1/discord/reports` | Bot-authenticated private submission; only `description` is required report content. The bot also supplies its asserted `discordUserId`. |
| `POST /v1/discord/reports/status` | Bot-authenticated lookup of minimal status records for the asserted Discord ID; never returns report text. |
| `POST /v1/discord/lead-notifications` | Bot-authenticated confirmation that the Lead was (or was not) actually notified about a pending Lead-required proposal; a confirmed delivery records the timestamp that starts the one-hour fallback clock. |
| `GET /v1/discord/reviewer-alerts`, `POST /v1/discord/reports/:id/reviewer-notification` | Trusted-bot feed of unannounced report IDs and durable delivery marker; no report text, reporter identity, or evidence links are returned. |
| `GET /v1/mvp/reports`, `GET /v1/mvp/reports/:id` | Reviewer-only private report queue and details. |
| `POST /v1/mvp/reports/:id/triage`, `/merge` | One-reviewer triage or duplicate merge. |
| `POST /v1/mvp/reports/:id/publication` | Propose first incident and cast the proposing reviewer's vote. |
| `POST /v1/mvp/incidents/:id/publication` | Propose a new version of a published incident. |
| `GET /v1/mvp/proposals/:id`, `POST /v1/mvp/proposals/:id/approval`, `/rejection`, `/evaluate`, `/cancel` | Private proposal audit, authenticated reviewer approval, rejection with an audit reason, clock re-evaluation, and Lead cancellation of a pending proposal. Any one reviewer may reject a draft proposal; it does not publish or expose the source report, which may be proposed again after revision. |
| `GET /v1/mvp/proposals/pending` | Reviewer-only feed of pending proposals that have the required non-Lead votes and still wait on the Lead; the trusted Discord bot uses it to DM the Lead and then confirm the delivery attempt. |
| `GET /v1/mvp/incidents`, `GET /v1/mvp/incidents/:id` | Reviewer-approved public incidents only. |
| `GET /v1/mvp/notifications/outbox` | Reviewer-only unsent Discord draft events. |

Reports receive sequential `R-####` IDs and public incidents receive separate `SEN-####` IDs, allocated atomically in the persistent JSON store. `description` is the only required report-content field; `projectId`, `incidentType` (default `not_sure`), `targets[]`, and `evidence[]` are optional. Report text, Discord identity, and suspicious target URLs stay private. A suspicious URL may have a query string and is stored as a lead only; this backend never fetches it. Public incident output contains only reviewer-written title, what-happened summary, verification note, level, severity, the "what you should do" action bullets, selected evidence references, version timeline, timestamps, and the independent-project disclaimer. Per Ollie's 5 October confirmation, **"What you should do" is 1-3 short, distinct action bullets and is required on every public level** (each bullet rejects embedded URLs and the reporter's Discord ID); false-alarm publication must use exactly the single bullet `No action needed.`. Public narrative fields reject embedded web URLs and the reporter's Discord ID. Selected public evidence must be a transaction hash or a reviewer-selected HTTPS statement without credentials, query, or fragment; the backend checks URL syntax only and cannot verify that a statement is actually official. Clients should display evidence URLs as inert text until a user deliberately opens a reviewer-selected source. A valid reference is **not** proof of malicious behavior; reviewers still judge evidence quality and must not copy raw private descriptions into public summaries.

The reviewer-alert feed returns only `{id, createdAt}` for submitted reports without a delivery timestamp. After successfully posting the ID to the private reviewer channel, the trusted bot records `reviewerNotifiedAt`. Reviewer detail commands should remain ephemeral and never publish report content or raw links in the channel.

The public `level` values are `informational`, `under_investigation`, `credible_threat`, `confirmed_incident`, `resolved`, and `false_alarm`. `severity` is separate (`critical`, `high`, `medium`, `low`); `informational` has `null` severity. New reports never publish automatically. One reviewer can open Information or Under Investigation with 1-3 "what you should do" action bullets. Credible Threat and medium/low Confirmed Incident require 2 of 3 configured reviewer votes and at least one explicitly selected public evidence reference. This is a minimum structural check, **not** the draft's independent/strong evidence standard; human reviewers must judge whether the evidence actually supports the level. High/critical Confirmed Incident and high/critical Resolved require 2 votes including the Lead; per Ollie's 3 October confirmation, **medium/low Resolved needs any one reviewer**, and **public False Alarm needs 2 of 3 reviewers without the Lead** (it may close any published incident that is not already closed and must retain the published severity). Reviewers cannot approve reports from their own configured Discord ID, and duplicate votes fail. Downgrading a high/critical confirmed incident also keeps the Lead requirement.

The Lead's **one-hour no-response fallback is now driven by a bot-confirmed notification clock** (Ollie, 3 October): when two non-Lead votes satisfy a Lead-required proposal, the trusted bot records `POST /v1/discord/lead-notifications` with `delivered: true`; the backend stores that confirmation timestamp (`leadNotifiedAt`) on the proposal and, if the fallback publishes, on the incident with `pendingLeadReview: true`. A `delivered: false` confirmation never starts the clock, and the fallback only fires after a full hour from the confirmed timestamp via `POST /v1/mvp/proposals/:id/evaluate`. A pending proposal records the reviewer roster and will not accept votes after that roster changes; the current Lead must cancel it and propose again. Informational and Under Investigation produce no Discord notification drafts until channel policy is settled; other publication drafts (including False Alarm closures) remain unsent. Telegram and X bot channels are outside the MVP. The backend remains loopback-only, with a single-process JSON store and no rate limiting; it is an integration prototype, not a deployed multiuser service.

This is an **MVP API foundation**, not the full product workflow. It has no deployed Discord bot, web OAuth session, verified source-author identity, image upload, automated notification delivery, reputation system, or production rate limiting. The public timeline currently records approved level changes and summaries; it does not yet model the richer investigation milestones in the product draft. The bot adapter must still be built so it actually calls the lead-notification endpoint after each real Discord delivery attempt; the backend records only what the trusted bot asserts.

## Legacy local demo mode

Without `DISCORD_BOT_TOKEN`, the old suspicious-contract workflow remains available for the existing demo. It demonstrates one case: a community report about a suspicious contract. Reports stay private until a reviewer makes a manual publication decision. Read-only Monad RPC checks provide transaction facts; they do not determine whether a contract is malicious.

### Run locally

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

### Hosted demo mode

For judge-accessible deployments (per Ollie's 5 October decision: lightweight managed hosting, one demo reviewer token as the main path, and a public no-login incidents page):

- `HOST` env var (default `127.0.0.1`); hosted environments set `HOST=0.0.0.0`. A `Dockerfile` is included for any container platform.
- In MVP mode `GET /` serves an **English public incidents page** (`public/mvp.html` + `mvp.css` + `mvp-app.js`): read-only, unauthenticated, renders `GET /v1/mvp/incidents`, shows the "what you should do" bullets, and carries the unified disclaimer footer including "Not financial advice". The legacy Chinese demo page still serves when MVP mode is off.
- `npm run seed` fills the store with **fictional** demo content: four private reports, three published incidents (`under_investigation`, `false_alarm`, `informational`), and one report deliberately kept private to demonstrate confidentiality. The script is idempotent — it skips when reports already exist, so it is safe to run on every boot.

Set `RPC_URL` to an HTTPS Monad RPC endpoint before starting the server to enable read-only transaction and watchlist checks. The report's chain ID must match the RPC chain ID. The RPC provider receives queried transaction hashes. No transaction is sent onchain.

### Implemented legacy flow

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
- Public alert responses list approved fields explicitly, including selected evidence and matching chain findings. Submission rejects clearly labelled seed phrases or private keys in report text and evidence notes; a transaction hash remains valid evidence. This conservative filter does not identify every possible secret, so the UI must continue warning people not to paste keys or recovery phrases.
- Reviewer text that can reach a public alert gets the same sensitive-content check. The local demo displays approved source URLs as defanged, non-clickable text in public alerts; reviewers can still open source links in their private view.
- Public alert payloads and notification drafts include the independent-project disclaimer from the product draft. The demo page shows that disclaimer and a reminder that Sentinel never asks for keys or wallet signatures.
- Published alerts have history, corrections, and retractions. Publication, correction, and retraction create local notification drafts; no Telegram, Discord, or user delivery occurs.
- A reviewer can manually inspect transaction receipts and logs from watchlisted addresses. The first watch check covers the latest 100 blocks; later checks resume after the saved block, advancing at most 500 blocks per request. Repeated logs are deduplicated by block hash and log index. These observations never assign a risk verdict.
- Contributor counts use self-declared reporter labels. They are not identity verification or a reputation score.

### Legacy integration endpoints

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

### Legacy limits before deployment

The shared token, self-declared reporter label, single-process JSON store, and loopback listener are for a local demo. Production authentication, storage, rate limiting, source credibility rules, notification delivery, and any onchain write design remain team decisions. Watch scans are manual and do not reconcile chain reorganizations. A successful transaction, matching target address, or manual `verified` status is not a guarantee that a contract is safe.
