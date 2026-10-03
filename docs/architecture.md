# Repository structure and integration boundaries

This layout follows Ollie's October 1 proposal while keeping each team's work separate. This pull request contains backend prototype workflows and interface contracts; the team frontend and Discord bot are still placeholders.

| Directory | Intended role | Current state |
| --- | --- | --- |
| `frontend/` | Dashboard and user interface | Ollie plans to deliver it; placeholder only |
| `backend/` | Incident reports, evidence, verification, alerts, read-only Monad checks | MVP API prototype plus isolated legacy demo; tests and fictional examples |
| `contracts/` | Optional onchain components | Placeholder; no contract or write path yet |
| `bot/` | Discord bot for the MVP | Ollie plans to deliver it; placeholder only. Telegram and X are after the hackathon |
| `docs/` | Product, verification, and architecture decisions | Product decision record, verification and architecture drafts |

The MVP backend accepts Discord bot submissions through `POST /v1/discord/reports`, keeps new reports private, and exposes an incident only after a reviewer explicitly publishes it. A reviewer selects which evidence may appear publicly. The frontend can read published incidents through `GET /v1/mvp/incidents`. Direct web submission still needs a trusted Discord identity adapter. The Discord bot can later consume publication events, but the present outbox is an unsent local draft list. The MVP contract is [`backend/mvp-openapi.json`](../backend/mvp-openapi.json). [`backend/openapi.json`](../backend/openapi.json) and the earlier fictional examples describe the isolated legacy demo; its `/v1/reports` and `/v1/alerts` endpoints are disabled when MVP mode is configured.

On 3 October, Ollie confirmed the MVP direction: one six-value public incident `level` field, separate `severity`, optional report targets and evidence, and Discord ID as the reporter identity. The MVP prototype maps distinct server-side bearer tokens to reviewer identities for local approval tests; one reviewer may triage or publish lower-risk information, while threat publication uses the agreed two-of-three rules. A requester-supplied reviewer or reporter name cannot establish identity. Both modes still use a loopback server and JSON storage; production authentication and a Discord identity integration remain to be built. See [`verification.md`](verification.md) for the policy and implementation boundary.

`backend/public/` contains a test page for the legacy demo and is disabled in MVP mode. It does not define Ollie's frontend implementation. `backend/src/rpc.mjs` reads Monad transaction and log data in legacy mode; watch checks save a block cursor and require another manual check when the gap is larger than 500 blocks. It does not classify contracts, reconcile chain reorganizations, or write onchain. The team still needs to agree on production authentication, storage, subscriptions, source credibility rules, and whether any contract is necessary.
