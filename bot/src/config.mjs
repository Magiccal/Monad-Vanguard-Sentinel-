// Trusted Discord adapter configuration. Every value comes from the environment;
// nothing is read from request bodies or chat messages (the adapter is the trust
// boundary asserted by the backend contract).
function required(name) {
  const value = process.env[name];
  if (!value) {
    console.error(`[sentinel-bot] missing required environment variable: ${name}`);
    process.exit(1);
  }
  return value;
}

export const config = {
  // Discord credentials of the bot application created in the Developer Portal.
  discordToken: required('DISCORD_BOT_TOKEN'),
  clientId: required('DISCORD_CLIENT_ID'),

  // Backend MVP API. The backend must be started with the SAME Discord bot token
  // (DISCORD_BOT_TOKEN) so the trusted-adapter bearer check passes; override with
  // BOT_BACKEND_TOKEN only when the backend expects a dedicated adapter secret.
  backendBaseUrl: process.env.BACKEND_BASE_URL ?? 'http://127.0.0.1:8787',
  botBackendToken: process.env.BOT_BACKEND_TOKEN ?? required('DISCORD_BOT_TOKEN'),

  // One of the configured reviewer bearer tokens, used only to poll the reviewer-only
  // notification outbox and the pending Lead proposals feed. It never grants reporters anything.
  reviewerToken: required('REVIEWER_TOKEN'),

  // Where approved incidents are posted and who gets the Lead approval DM.
  alertChannelId: required('ALERT_CHANNEL_ID'),
  leadDiscordId: required('LEAD_DISCORD_ID'),

  pollIntervalMs: Math.max(5000, Number(process.env.POLL_INTERVAL_MS ?? 30000)),
};
