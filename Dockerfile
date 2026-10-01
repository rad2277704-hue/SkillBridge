FROM node:22-bookworm-slim

ENV NODE_ENV=production \
    BIND_HOST=0.0.0.0 \
    REMOTE_API_ENABLED=true \
    DATABASE_PATH=/data/skillbridge.db

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app /data \
    && chown -R node:node /app /data

WORKDIR /app
USER node

COPY --chown=node:node backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node backend/ ./

EXPOSE 3000
CMD ["node", "server.js"]
