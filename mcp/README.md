# sentinel_check MCP

MCP server exposing the Sentinel check API (issue #8, phase 2) to any agent.
Read-only: it calls `GET /v1/check` on a running Sentinel backend and relays the
human-verified result. It never publishes or mutates anything.

## Safety rules (baked into the tool description)

- `credible_threat` / `confirmed_incident` → the tool tells the agent to **STOP
  and ask a human** before any action involving the target.
- `none` (no verified incident) → the tool tells the agent the target is
  **UNKNOWN, not safe**: absence of an incident is not a safety guarantee.

## Configuration

```json
{
  "mcpServers": {
    "sentinel_check": {
      "command": "node",
      "args": ["/path/to/repo/mcp/src/index.mjs"],
      "env": {
        "SENTINEL_CHECK_BASE_URL": "https://sentinel-security-demo.app.workbuddy.host"
      }
    }
  }
}
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `SENTINEL_CHECK_BASE_URL` | hosted demo | Base URL of a Sentinel backend serving `GET /v1/check` |
| `SENTINEL_CHECK_TIMEOUT_MS` | `10000` | Upstream request timeout |

## Run

```sh
cd mcp && npm install
npm start        # stdio MCP server
npm test         # node --test (spawns the server against a stub API)
```
