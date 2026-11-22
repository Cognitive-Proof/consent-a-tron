# The trust registry. Build from the repository root (it serves the shared
# stylesheet and wallet client):  docker build -f registry/Dockerfile .
FROM node:22-bookworm-slim AS build
WORKDIR /app/registry
COPY registry/package.json registry/package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY registry/tsconfig.json ./
COPY registry/src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
WORKDIR /app/registry
COPY --from=build /app/registry/node_modules ./node_modules
COPY --from=build /app/registry/dist ./dist
COPY registry/package.json ./
COPY wallet/src/style.css /app/wallet/src/style.css
COPY crates/demo-common/src/wallet-client.js /app/crates/demo-common/src/wallet-client.js
# PKI material comes from Secret Manager as PKI_* environment variables.
ENV APP_ROOT=/app NODE_ENV=production
USER node
CMD ["node", "dist/server.js"]
