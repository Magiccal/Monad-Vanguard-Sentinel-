# Repository structure and integration boundaries

This layout follows Ollie's October 1 proposal while keeping each team's work separate. Only the backend demo and its interface draft are implemented in this pull request.

| Directory | Intended role | Current state |
| --- | --- | --- |
| `frontend/` | Dashboard and user interface | Ollie plans to deliver it; placeholder only |
| `backend/` | Incident reports, evidence, verification, alerts, read-only Monad checks | Working local demo and tests |
| `contracts/` | Optional onchain components | Placeholder; no contract or write path yet |
| `bot/` | Discord and Telegram delivery | Ollie plans to deliver it; placeholder only |
| `docs/` | Product, verification, and architecture decisions | Verification and architecture drafts |

The backend accepts community reports, keeps them private during review, and exposes alerts only after a reviewer publishes them. A reviewer selects which evidence may appear publicly. The frontend can read public alerts through `GET /v1/alerts` and submit reports through `POST /v1/reports`. The bots can later consume publication events, but the present outbox is an unsent local draft list. The complete interface draft is [`backend/openapi.json`](../backend/openapi.json), with fictional integration payloads in [`backend/examples/`](../backend/examples/README.md).

`backend/public/` contains a test page served by the backend. It helps demonstrate the workflow and does not define Ollie's frontend implementation. `backend/src/rpc.mjs` reads Monad transaction and log data; watch checks save a block cursor and require another manual check when the gap is larger than 500 blocks. It does not classify contracts, reconcile chain reorganizations, or write onchain. The team still needs to agree on production authentication, storage, subscriptions, source credibility rules, and whether any contract is necessary.
