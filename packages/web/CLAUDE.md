# Package: web

**Purpose:** Public registry website. Next.js 15 / React 19. Searchable, publicly accessible at mcp-sentinel.com.

## Key Files
- `app/` — Next.js App Router pages
- `next.config.ts` — Next.js config
- `package.json` — dependencies: Next.js 15, React 19 only (minimal)

## Current Build State

| Page | Status | Notes |
|------|--------|-------|
| `/` (home) | ✅ Exists | Search UI not connected to API |
| `/about` | ✅ Exists | — |
| `/dashboard` | ✅ Exists | Ecosystem stats not wired |
| `/server/[slug]` | ✅ Exists | Server detail not wired |
| `not-found` | ✅ Exists | — |

**Primary gap:** Search and server detail pages exist as shells but are not connected to the REST API at `packages/api/`. This is the Layer 3 blocking deliverable.

## API Integration
The web package calls `packages/api/` endpoints. API base URL should come from env:
```typescript
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:4000";
```

## What NOT to Build (per product-milestones.md)
- User authentication — public read-only registry only
- Payment/billing UI
- LLM-powered search or summaries
- Mobile-specific UI
- Admin dashboards

## What NOT to Do
- Do NOT add server-side DB access — all data comes through the REST API
- Do NOT inline API URLs — always use `NEXT_PUBLIC_API_URL` env var
- Do NOT add heavy client-side dependencies — keep the bundle lean
