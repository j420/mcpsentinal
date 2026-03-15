FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@10.29.3 --activate

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./
COPY packages/web/package.json ./packages/web/
RUN pnpm install --frozen-lockfile --filter=@mcp-sentinel/web...

COPY packages/web/ ./packages/web/
ENV NEXT_TELEMETRY_DISABLED=1

ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL

RUN pnpm --filter=@mcp-sentinel/web build

# ─── Runner ───────────────────────────────────────────────────────────────────
# Uses next start (not standalone) to avoid pnpm virtual-store tracing issues.
FROM base AS runner
WORKDIR /app/packages/web
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

COPY --from=builder --chown=nextjs:nodejs /app/node_modules /app/node_modules
COPY --from=builder --chown=nextjs:nodejs /app/packages/web /app/packages/web

USER nextjs
EXPOSE 3000
# Pass $PORT so next start listens on the port Railway routes traffic to.
# Invoke next directly (no pnpm) — runner stage has no workspace root package.json.
CMD ["sh", "-c", "/app/node_modules/.bin/next start -p ${PORT:-3000}"]
