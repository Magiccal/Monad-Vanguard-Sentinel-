# API examples for frontend and bot integration

These fictional JSON files show the two **separate** local API modes. The IDs and timestamps are illustrative; a running server creates its own IDs. The backend serves only on localhost. New bot and frontend work should use [`mvp-openapi.json`](../mvp-openapi.json) and the MVP examples below. The old `openapi.json` and legacy examples only run when MVP mode is disabled.

| File | MVP endpoint | Audience |
| --- | --- | --- |
| [`discord-report-request.json`](discord-report-request.json) | `POST /v1/discord/reports` request | Trusted Discord bot adapter only |
| [`mvp-private-report.json`](mvp-private-report.json) | `GET /v1/mvp/reports/:id` illustrative private response | Reviewer UI only |
| [`mvp-publication-request.json`](mvp-publication-request.json) | `POST /v1/mvp/reports/:id/publication` request | Reviewer UI only |
| [`mvp-incidents-response.json`](mvp-incidents-response.json) | `GET /v1/mvp/incidents` illustrative response after two approvals | Public frontend |

The bot must extract `discordUserId` from a Discord interaction and authenticate with the **server-side** `DISCORD_BOT_TOKEN`. It is an assertion by the trusted bot; this backend does not verify Discord signatures. The example publication request uses the evidence ID from the private report. A higher-level publication remains pending until independent configured reviewer tokens approve it. The public response omits reporter identity, raw report text, suspicious target URLs, and private evidence notes. Do not use the old `/v1/reports` route for MVP submissions; it is disabled when the MVP service is enabled.

## Legacy local demo examples

| File | Endpoint | Audience |
| --- | --- | --- |
| [`report-request.json`](report-request.json) | `POST /v1/reports` request | Frontend |
| [`report-created.json`](report-created.json) | `POST /v1/reports` response | Frontend |
| [`review-decision-request.json`](review-decision-request.json) | `POST /v1/reports/:id/decision` request | Reviewer UI |
| [`alerts-response.json`](alerts-response.json) | `GET /v1/alerts` response | Frontend |
| [`notification-outbox-response.json`](notification-outbox-response.json) | `GET /v1/notifications/outbox` response | Bot integration draft |
| [`watch-check-response.json`](watch-check-response.json) | `POST /v1/watchlist/:id/check` response | Reviewer UI |
| [`error-response.json`](error-response.json) | `400` invalid report | Any client |
| [`unauthorized-response.json`](unauthorized-response.json) | `401` missing reviewer token | Reviewer UI or bot integration |
| [`conflict-response.json`](conflict-response.json) | `409` invalid state change | Reviewer UI |
| [`rpc-not-configured-response.json`](rpc-not-configured-response.json) | `503` optional RPC unavailable | Reviewer UI |

Start the backend using the steps in [`backend/README.md`](../README.md). Then submit the example report:

```bash
curl -sS -X POST http://127.0.0.1:8787/v1/reports \
  -H 'Content-Type: application/json' \
  --data-binary @examples/report-request.json
```

The returned report ID is private until review. Reviewer routes require `Authorization: Bearer <REVIEWER_TOKEN>`. For a real decision request, first read `GET /v1/reports/:id` and replace the example `publicEvidenceIds` with the returned evidence IDs. After publication, the frontend may read `GET /v1/alerts`. The outbox is reviewer-protected and contains **unsent drafts**; bot delivery and retry behavior are not yet implemented.

Clients should handle `{ "error": "...", "message": "..." }` on non-2xx responses. Error messages explain the specific failure and can change; clients should branch on the HTTP status and `error` code. The full machine-readable contract is [`backend/openapi.json`](../openapi.json).
