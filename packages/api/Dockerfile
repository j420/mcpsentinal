FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@10.29.3 --activate

# ─── Builder ──────────────────────────────────────────────────────────────────
FROM base AS builder
WORKDIR /app

# tree-sitter / tree-sitter-python (transitive via @mcp-sentinel/analyzer) compile
# native bindings during postinstall — alpine needs python3 + a C++ toolchain.
# Listed in root package.json's pnpm.onlyBuiltDependencies.
RUN apk add --no-cache python3 make g++

COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./

# Stage every workspace package.json the API transitively depends on.
COPY packages/database/package.json           ./packages/database/
COPY packages/analyzer/package.json           ./packages/analyzer/
COPY packages/red-team/package.json           ./packages/red-team/
COPY packages/risk-matrix/package.json        ./packages/risk-matrix/
COPY packages/attack-graph/package.json       ./packages/attack-graph/
COPY packages/compliance-reports/package.json ./packages/compliance-reports/
COPY packages/api/package.json                ./packages/api/

RUN pnpm install --frozen-lockfile --filter=@mcp-sentinel/api...

# Now copy full sources for everything in the build closure.
COPY packages/database/           ./packages/database/
COPY packages/analyzer/           ./packages/analyzer/
COPY packages/red-team/           ./packages/red-team/
COPY packages/risk-matrix/        ./packages/risk-matrix/
COPY packages/attack-graph/       ./packages/attack-graph/
COPY packages/compliance-reports/ ./packages/compliance-reports/
COPY packages/api/                ./packages/api/

# Cache-bust: Railway sets RAILWAY_GIT_COMMIT_SHA per deploy.
# This ensures the build step always runs fresh (no stale Docker layer cache).
ARG RAILWAY_GIT_COMMIT_SHA
ENV BUILD_SHA=$RAILWAY_GIT_COMMIT_SHA

# turbo.json sets build.dependsOn = ["^build"], so turbo computes topological
# order from package.json deps automatically. Replaces the previous explicit
# `pnpm --filter <pkg> build` lines and won't drift if more deps are added.
RUN pnpm turbo run build --filter=@mcp-sentinel/api...

# Ensure per-package node_modules dirs exist so runner COPY never fails for
# pure-TS packages whose deps are fully hoisted (mirrors web Dockerfile).
RUN mkdir -p \
  /app/packages/database/node_modules \
  /app/packages/analyzer/node_modules \
  /app/packages/red-team/node_modules \
  /app/packages/risk-matrix/node_modules \
  /app/packages/attack-graph/node_modules \
  /app/packages/compliance-reports/node_modules \
  /app/packages/api/node_modules

# ─── Runner ───────────────────────────────────────────────────────────────────
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Workspace deps (dist + package.json + node_modules each).
COPY --from=builder /app/packages/database/dist            ./packages/database/dist
COPY --from=builder /app/packages/database/package.json    ./packages/database/package.json
COPY --from=builder /app/packages/database/node_modules    ./packages/database/node_modules

COPY --from=builder /app/packages/analyzer/dist            ./packages/analyzer/dist
COPY --from=builder /app/packages/analyzer/package.json    ./packages/analyzer/package.json
COPY --from=builder /app/packages/analyzer/node_modules    ./packages/analyzer/node_modules

COPY --from=builder /app/packages/red-team/dist            ./packages/red-team/dist
COPY --from=builder /app/packages/red-team/package.json    ./packages/red-team/package.json
COPY --from=builder /app/packages/red-team/node_modules    ./packages/red-team/node_modules

COPY --from=builder /app/packages/risk-matrix/dist         ./packages/risk-matrix/dist
COPY --from=builder /app/packages/risk-matrix/package.json ./packages/risk-matrix/package.json
COPY --from=builder /app/packages/risk-matrix/node_modules ./packages/risk-matrix/node_modules

COPY --from=builder /app/packages/attack-graph/dist            ./packages/attack-graph/dist
COPY --from=builder /app/packages/attack-graph/package.json    ./packages/attack-graph/package.json
COPY --from=builder /app/packages/attack-graph/node_modules    ./packages/attack-graph/node_modules

COPY --from=builder /app/packages/compliance-reports/dist            ./packages/compliance-reports/dist
COPY --from=builder /app/packages/compliance-reports/package.json    ./packages/compliance-reports/package.json
COPY --from=builder /app/packages/compliance-reports/node_modules    ./packages/compliance-reports/node_modules

COPY --from=builder /app/packages/api/dist          ./packages/api/dist
COPY --from=builder /app/packages/api/package.json  ./packages/api/package.json
COPY --from=builder /app/packages/api/node_modules  ./packages/api/node_modules

COPY --from=builder /app/node_modules ./node_modules

EXPOSE 3100
CMD ["node", "packages/api/dist/server.js"]
