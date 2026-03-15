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

RUN pnpm --filter=@mcp-sentinel/web build

# ─── Runner ───────────────────────────────────────────────────────────────────
# Mirrors packages/api/Dockerfile: compile → copy output → node directly. No pnpm at runtime.
#
# With output:"standalone" + outputFileTracingRoot="/app", next build produces:
#   packages/web/.next/standalone/
#     node_modules/        ← flat real files, NOT pnpm symlinks (@vercel/nft dereferences them)
#     packages/web/
#       server.js          ← HTTP server entry point (reads process.env.PORT automatically)
#       package.json
#
# Static assets and public/ must be copied separately — standalone excludes them by design.
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0

RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

# Standalone output extracted to /app — gives us /app/packages/web/server.js + /app/node_modules/
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/.next/standalone ./

# Static assets: server.js expects them at packages/web/.next/static/ relative to WORKDIR
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/.next/static ./packages/web/.next/static

# Public assets: server.js expects them at packages/web/public/ relative to WORKDIR
RUN mkdir -p packages/web/public
COPY --from=builder --chown=nextjs:nodejs /app/packages/web/public ./packages/web/public

USER nextjs
EXPOSE 3000

# Standalone server.js reads process.env.PORT set by Railway — no flag needed.
CMD ["node", "packages/web/server.js"]
