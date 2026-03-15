FROM node:20-alpine
RUN corepack enable && corepack prepare pnpm@10.29.3 --activate

WORKDIR /app

# Copy workspace config + web package source
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json tsconfig.base.json ./
COPY packages/web/ ./packages/web/

# Install only web package and its dependencies
RUN pnpm install --frozen-lockfile --filter=@mcp-sentinel/web...

# NEXT_PUBLIC_* vars must be baked at build time
ARG NEXT_PUBLIC_API_URL
ARG NEXT_PUBLIC_SITE_URL
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_SITE_URL=$NEXT_PUBLIC_SITE_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN pnpm --filter=@mcp-sentinel/web build

WORKDIR /app/packages/web
ENV NODE_ENV=production
EXPOSE 3000

# pnpm exec works because /app/package.json + pnpm-workspace.yaml are present.
CMD ["sh", "-c", "pnpm exec next start -p ${PORT:-3000}"]
