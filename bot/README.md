# Sentinel Discord bot (MVP adapter)

Ollie confirmed on 3 October that Discord is the only bot channel for the MVP; Telegram
and X follow after the hackathon. On 2026-10-06 he assigned this adapter as the next task:
create the bot application, wire the four `/sentinel` commands, post approved incidents to
the public channel, and DM the Lead for critical/high approvals. The backend holds the
review workflow and never sends Discord messages itself; this bot is the only delivery
path. It takes `discordUserId` from a verified Discord interaction and must not treat a
typed name as identity. The backend trusts the authenticated bot adapter and does not
verify Discord interaction signatures itself.

## What it does

1. **`/sentinel report`** — submits a private report through `POST /v1/discord/reports`.
   Only the description is required; project, incident type, a suspicious URL/address and
   one evidence link or transaction hash are optional. The report stays private until a
   reviewer opens it. The reporter's Discord user ID is asserted from the interaction,
   never typed by the user.
2. **`/sentinel check [SEN-####]`** — public lookup of a published incident (or the latest
   five), showing level, severity, summary, "What you should do" bullets and the disclaimer.
3. **`/sentinel status R-####`** — minimal private status of one of your own reports
   (the bot can never read report text).
4. **`/sentinel myreports`** — minimal status of all reports tied to your Discord ID.
5. **Alerts loop** — polls the reviewer-only notification outbox (`GET /v1/mvp/notifications/outbox`)
   and posts every newly published incident to **#sentinel-alerts** with level, severity,
   action bullets and the unified disclaimer footer (including "Not financial advice").
6. **Lead loop** — polls `GET /v1/mvp/proposals/pending` (new reviewer-only feed added in
   this change) and DMs the Lead about each proposal waiting on their approval, then calls
   `POST /v1/discord/lead-notifications` with `delivered: true` only after the DM was
   actually sent. A failed DM confirms `delivered: false`, which never starts the one-hour
   fallback clock (Ollie, 2026-10-03).

## One-time setup (Discord Developer Portal)

1. Go to <https://discord.com/developers/applications> → **New Application** → name it
   (e.g. "Monad Sentinel") → copy the **Application ID** (`DISCORD_CLIENT_ID`).
2. In **Bot**: copy the bot token (`DISCORD_BOT_TOKEN`). Keep it secret; it is also the
   trusted-adapter bearer the backend expects.
3. The bot needs **no** privileged gateway intents (guild + interaction events only).
4. Build the invite URL in **OAuth2 → URL Generator**: scopes `bot` + `applications.commands`;
   bot permissions `Send Messages` (2048), `Embed Links` (16384), `Attach Files` (32768) —
   combined value `51200` — or add
   `Administrator` only on a private test server. Send the generated URL to the server
   owner (Ollie) so the bot joins the server with the channels he already created
   (#sentinel-alerts public, #reviewers private, Reviewer role).

## Configuration

| Variable | Meaning |
| --- | --- |
| `DISCORD_BOT_TOKEN` | Bot token from the Developer Portal (required) |
| `DISCORD_CLIENT_ID` | Application ID, used for slash-command registration (required) |
| `REVIEWER_TOKEN` | One configured backend reviewer token, used only to poll the outbox and pending-Lead feeds (required) |
| `ALERT_CHANNEL_ID` | Discord channel ID of the public `#sentinel-alerts` channel (required) |
| `LEAD_DISCORD_ID` | Discord user ID of the Lead, for approval DMs (required) |
| `BACKEND_BASE_URL` | MVP backend base URL (default `http://127.0.0.1:8787`) |
| `BOT_BACKEND_TOKEN` | Overrides the bearer used against the backend (default: the Discord bot token) |
| `POLL_INTERVAL_MS` | Polling interval for both delivery loops (default `30000`) |

Start the backend in MVP mode with the **same** `DISCORD_BOT_TOKEN` value so the trusted
adapter bearer check passes (see `../backend/README.md`), then:

```bash
cd bot
npm install
DISCORD_BOT_TOKEN=... DISCORD_CLIENT_ID=... npm run register   # once, or after editing commands
DISCORD_BOT_TOKEN=... DISCORD_CLIENT_ID=... REVIEWER_TOKEN=... \
ALERT_CHANNEL_ID=... LEAD_DISCORD_ID=... npm start
```

**Proxy note**: if your network needs an HTTP proxy to reach `discord.com` (the API and
the gateway both), set `HTTPS_PROXY` for the registration script — `register.mjs` routes
discord.js through undici's `ProxyAgent` when `HTTPS_PROXY` is set (verified with a local
Clash instance on `127.0.0.1:7890`). The same applies to any long-running bot process:
either run it on a host with direct Discord reachability or set `HTTPS_PROXY` with an
undici global dispatcher (the runtime code currently assumes direct connectivity; wire
the same ProxyAgent into `index.mjs` when deploying behind a proxy).

Verified setup (2026-10-06): application ID `1557042036106854510`, global `/sentinel`
command registered with the four subcommands `report`, `check`, `status`, `myreports`.

## Notes and limits

- Report contents, Discord identities and suspicious targets stay private; the status
  commands expose only `R-####` IDs, status names and timestamps.
- The dedupe sets are in-memory; after a restart the loops may re-post one alert or re-DM
  the Lead once at most. Production dedupe belongs to the persistence discussion.
- Delivery, subscriptions, retries, and production authentication still need integration
  work; the backend records only what this trusted adapter asserts.
- The MVP contract lives in [`backend/mvp-openapi.json`](../backend/mvp-openapi.json).
