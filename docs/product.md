# MVP decisions from Ollie

Source: Ollie's Telegram reply shown at 02:14 Beijing time on 3 October 2026, following review of draft PR #2. This records agreed product direction. The backend README and OpenAPI describe what the local demo currently implements; this document does not imply that the frontend or Discord bot is already integrated.

## Incidents and publication

- Public incidents use one `level` field: `informational`, `under_investigation`, `credible_threat`, `confirmed_incident`, `resolved`, or `false_alarm`.
- `severity` is separate: `critical`, `high`, `medium`, or `low`. It is `null` for `informational`.
- A new report is private. `informational` and `under_investigation` may become public only when a reviewer opens them, with a calm “what to do” line.
- `SEN-####` identifies incidents and `R-####` identifies reports. A report ID does not make its contents public.

## Reviewer approvals

The team has three reviewers; Ollie is the Lead. No reviewer may approve their own report.

| Action | Agreed approval rule |
| --- | --- |
| Triage, merge duplicates, publish `informational`, or open `under_investigation` | One reviewer |
| Publish `credible_threat` at any severity, or `confirmed_incident` at medium/low severity | Two of three reviewers |
| Publish `confirmed_incident` or `resolved` at critical/high severity | Two of three reviewers, including the Lead |

If the Lead has not responded within one hour, any two reviewers may publish a critical/high `confirmed_incident` or `resolved` item; the Lead reviews it afterwards. A single-reviewer demo is acceptable if the API shape can represent the approval model. This does not make a shared token or a client-provided reviewer name suitable for production voting.

The exact trigger for the one-hour fallback, handling of medium/low `resolved`, and production reviewer identity/authentication remain integration details to confirm. Until then, do not silently grant a broader approval path.

Selected public evidence still needs human source verification. A URL entered under `official_statement` is a reporter's claim; URL syntax checks alone cannot establish that it belongs to a project or that the statement is genuine.

## Report intake and channels

Only `description` is required. Optional fields are `projectId`, `incidentType` (default `not_sure`), `targets[]` (address, hash, URL, or X handle), and `evidence[]` (transaction, link, screenshot, or official statement). The reporter is keyed to their verified Discord ID, not a name typed into the form. The web app and bot need a trusted way to pass that identity to the backend; a self-declared field is only a local demo placeholder.

Discord is the only bot channel for the hackathon MVP. Telegram and X bot/channel support follow after the hackathon. An X handle can still be an incident target.
