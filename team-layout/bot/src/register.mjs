// Registers the global /sentinel slash command for the application.
// Run once (or after changing commands.mjs): DISCORD_BOT_TOKEN=... DISCORD_CLIENT_ID=... npm run register
// Registration only needs the bot token and application ID; the runtime env vars
// (REVIEWER_TOKEN, ALERT_CHANNEL_ID, LEAD_DISCORD_ID) are required by `npm start` only.
import { REST, Routes } from 'discord.js';
// discord.js does not honor HTTP(S)_PROXY on its own; route it through undici's
// ProxyAgent when HTTPS_PROXY is set (e.g. local Clash on 127.0.0.1:7890).
import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { sentinelCommand } from './commands.mjs';

const token = process.env.DISCORD_BOT_TOKEN;
const clientId = process.env.DISCORD_CLIENT_ID;
if (!token || !clientId) {
  console.error('[sentinel-bot] register requires DISCORD_BOT_TOKEN and DISCORD_CLIENT_ID');
  process.exit(1);
}
const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
if (proxy) setGlobalDispatcher(new ProxyAgent(proxy));

const rest = new REST().setToken(token);
const route = Routes.applicationCommands(clientId);
const existing = await rest.get(route);
if (Array.isArray(existing) && existing.length) await rest.put(route, { body: [] });
const result = await rest.put(route, { body: [sentinelCommand] });
console.log(`[sentinel-bot] registered ${result.length} global command(s).`);
