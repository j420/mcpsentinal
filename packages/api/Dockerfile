FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@10.29.3 --activate

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./
COPY packages/database/package.json ./packages/database/
COPY packages/risk-matrix/package.json ./packages/risk-matrix/
COPY packages/api/package.json ./packages/api/
RUN pnpm install --frozen-lockfile --filter=@mcp-sentinel/api...

COPY packages/database/ ./packages/database/
COPY packages/risk-matrix/ ./packages/risk-matrix/
COPY packages/api/ ./packages/api/

# Cache-bust: Railway sets RAILWAY_GIT_COMMIT_SHA per deploy.
# This ensures the build step always runs fresh (no stale Docker layer cache).
ARG RAILWAY_GIT_COMMIT_SHA
ENV BUILD_SHA=$RAILWAY_GIT_COMMIT_SHA

RUN pnpm --filter=@mcp-sentinel/database build
RUN pnpm --filter=@mcp-sentinel/risk-matrix build
RUN pnpm --filter=@mcp-sentinel/api build

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/packages/api/dist ./packages/api/dist
COPY --from=builder /app/packages/api/package.json ./packages/api/package.json
COPY --from=builder /app/packages/database/dist ./packages/database/dist
COPY --from=builder /app/packages/database/package.json ./packages/database/package.json
COPY --from=builder /app/packages/risk-matrix/dist ./packages/risk-matrix/dist
COPY --from=builder /app/packages/risk-matrix/package.json ./packages/risk-matrix/package.json
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages/api/node_modules ./packages/api/node_modules
COPY --from=builder /app/packages/database/node_modules ./packages/database/node_modules
COPY --from=builder /app/packages/risk-matrix/node_modules ./packages/risk-matrix/node_modules

EXPOSE 3100
CMD ["node", "packages/api/dist/server.js"]
