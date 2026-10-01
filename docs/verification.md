# Verification and evidence workflow

This document describes the current backend demo, not an approved incident policy. Reviewers must still agree on the evidence threshold for each public classification.

1. `POST /v1/reports` accepts a suspected-contract report with at least one transaction hash or public HTTPS source. It returns a report ID; the report is private and `submitted`.
2. A reviewer starts investigation, may add evidence, and may request read-only Monad transaction checks. RPC observations record chain facts and never make a threat decision.
3. The reviewer records a reason and either rejects the report or publishes it as `credible_threat` or `confirmed_incident`. Publication requires an action recommendation and explicit IDs of the evidence approved for public display.
4. `GET /v1/alerts` exposes active published alerts. `GET /v1/alerts/history` also includes corrections and retractions. Reporter identity, evidence contributor identity, and unapproved evidence stay out of public responses.
5. Publication, correction, and retraction create local notification drafts for future bot integration. They are not sent to users.

The current demo uses one server-configured reviewer identity, a shared local token, and a single-process JSON store. These are integration placeholders, not production authentication or persistence. The request and response schemas are in [`backend/openapi.json`](../backend/openapi.json), with fictional examples in [`backend/examples/`](../backend/examples/README.md). Manual watch checks remember the last scanned block and continue in bounded batches; they do not reconcile chain reorganizations.
