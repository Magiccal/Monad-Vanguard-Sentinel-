# Sentinel backend demo (MVP mode required at runtime via DISCORD_BOT_TOKEN + REVIEWERS_JSON)
FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY src/ src/
COPY public/ public/
COPY scripts/ scripts/
COPY mvp-openapi.json openapi.json ./
ENV NODE_ENV=production
EXPOSE 8787
# Bind 0.0.0.0 for hosted environments; configure via env:
#   HOST=0.0.0.0 PORT=8787 DATA_FILE=/tmp/sentinel.json REVIEWERS_JSON='[...]' DISCORD_BOT_TOKEN=...
CMD ["sh", "-c", "npm run seed && HOST=${HOST:-0.0.0.0} node src/server.mjs"]
