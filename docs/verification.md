# Verification and evidence workflow

This document separates Ollie's 3 October MVP decisions from the older backend demo flow. The agreed approval counts do not define an evidence threshold or production authentication. See [`product.md`](product.md) for the full decision record and remaining integration questions.

## Agreed MVP review policy

New reports stay private. A reviewer may publish `informational` or open `under_investigation` with a calm action line. `credible_threat` and medium/low `confirmed_incident` require two of three reviewers. Critical/high `confirmed_incident` or `resolved` require two of three including the Lead, with a one-hour nonresponse fallback followed by Lead review. No one may approve their own report. One reviewer may triage and merge duplicates. The demo may use one reviewer as long as the API can represent approvals; this is not a production quorum.

`level` and `severity` are separate. `informational` has null severity. `false_alarm`, `resolved`, and corrections need explicit transitions; the Telegram reply did not fully settle every transition and notification rule. Evidence standards, reviewer identity, and the one-hour timer's trigger also need operational agreement.

## MVP backend contract

The draft MVP implementation exposes private report intake at `POST /v1/discord/reports` to a trusted Discord bot adapter. Reviewer-only endpoints under `/v1/mvp/reports` and `/v1/mvp/proposals` record triage, duplicate merges, publication proposals, and individually authenticated votes. `GET /v1/mvp/incidents` returns only explicitly published incident fields; it does not return the source report or reporter Discord ID. Higher-confidence publication requires explicitly selected evidence references, but code-level validation is not a substitute for human source assessment. Discord notifications are stored as unsent drafts. The complete MVP request and response shapes are in [`backend/mvp-openapi.json`](../backend/mvp-openapi.json).

MVP mode disables the older `/v1/reports` and `/v1/alerts` demo routes to prevent bypassing the reviewer quorum. The backend has no trusted Lead notification-delivery timestamp, so the one-hour nonresponse exception remains disabled. Direct web authentication, production persistence, and Discord message delivery are not implemented.

## Earlier single-reviewer demo flow

The steps below document the original prototype, separate from the newer MVP endpoints. They do not implement Ollie's newly agreed multi-reviewer policy. The agreed rules and open questions are in [`product.md`](product.md).

1. `POST /v1/reports` accepts a suspected-contract report with at least one transaction hash or public HTTPS source. It returns a report ID; the report is private and `submitted`.
2. A reviewer starts investigation, may add evidence, and may request read-only Monad transaction checks. RPC observations record chain facts and never make a threat decision.
3. The reviewer records a reason and either rejects the report or publishes it as `credible_threat` or `confirmed_incident`. Publication requires an action recommendation and explicit IDs of the evidence approved for public display.
4. `GET /v1/alerts` exposes active published alerts. `GET /v1/alerts/history` also includes corrections and retractions. Reporter identity, evidence contributor identity, and unapproved evidence stay out of public responses.
5. Publication, correction, and retraction create local notification drafts for future bot integration. They are not sent to users.

The legacy demo uses one server-configured reviewer identity, a shared local token, and a single-process JSON store. These are integration placeholders, not production authentication or persistence. The request and response schemas are in [`backend/openapi.json`](../backend/openapi.json), with fictional examples in [`backend/examples/`](../backend/examples/README.md). Manual watch checks remember the last scanned block and continue in bounded batches; they do not reconcile chain reorganizations.
