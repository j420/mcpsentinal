FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@10.29.3 --activate

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./
COPY packages/web/ ./packages/web/

RUN pnpm install --frozen-lockfile --filter=@mcp-sentinel/web...

# NEXT_PUBLIC_* vars are baked into the JS bundle at build time — must be build ARGs.
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL
ENV NEXT_TELEMETRY_DISABLED=1

# Cache-bust: Railway sets RAILWAY_GIT_COMMIT_SHA per deploy.
# This ensures the build step always runs fresh (no stale Docker layer cache).
ARG RAILWAY_GIT_COMMIT_SHA
ENV BUILD_SHA=$RAILWAY_GIT_COMMIT_SHA

RUN pnpm --filter=@mcp-sentinel/web build

# Ensure per-package node_modules dir exists so runner COPY never fails
RUN mkdir -p /app/packages/web/node_modules

# ─── Runner ───────────────────────────────────────────────────────────────────
# Same pattern as packages/api/Dockerfile (which works):
#   compile → copy output + full node_modules → node directly, no pnpm.
#
# Why standalone node_modules alone fails: @vercel/nft traces through pnpm's
# virtual-store symlinks and misses packages. Solution: extract standalone for
# server.js location/structure, then OVERRIDE its traced node_modules with the
# builder's full pnpm install — guaranteed complete because pnpm installed it.
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# Standalone server.js reads HOSTNAME; must be 0.0.0.0 not localhost for Railway
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

# Step 1: Extract standalone structure.
# With output:'standalone' + outputFileTracingRoot='/app', this produces:
#   /app/packages/web/server.js   ← HTTP entry point (reads process.env.PORT)
#   /app/packages/web/package.json
#   /app/node_modules/            ← @vercel/nft-traced deps (may be incomplete)
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/.next/standalone ./

# Step 2: Override with the builder's full pnpm node_modules.
# The pnpm virtual store has relative internal symlinks — they copy correctly
# and Node resolves them the same way it does at build time. This is identical
# to what packages/api/Dockerfile does and is proven to work.
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules

# Step 3: Per-package node_modules (handles any pnpm-hoisted package splits).
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/node_modules ./packages/web/node_modules

# Step 4: Static assets — standalone excludes these by design.
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/.next/static ./packages/web/.next/static

# Step 5: Public assets.
RUN mkdir -p packages/web/public
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/public ./packages/web/public

USER nextjs
# Railway routes to this port; sets process.env.PORT=3000 (matching EXPOSE).
EXPOSE 3000

# server.js reads process.env.PORT (set by Railway via EXPOSE 3000) and HOSTNAME.
CMD ["node", "packages/web/server.js"]
