# Package: database

**Purpose:** PostgreSQL schema, migrations, Zod schemas, and all database queries. This is the ONLY package that contains SQL.

## The Boundary Rule

```
ALL SQL lives in: packages/database/queries/
ALL other packages import from: @mcp-sentinel/database

No exceptions.
```

This is enforced by `.claude/hooks/post-edit/no-inline-sql.sh`.
It is also ADR-004 in `agent_docs/architecture.md`.

## Key Files
- `src/schemas.ts` — Zod schemas + TypeScript types (single source of truth)
- `src/queries.ts` — `DatabaseQueries` class — all SQL in one place
- `src/migrate.ts` — migration runner
- `src/seed.ts` — development seed data
- `src/reset.ts` — `pnpm db:reset`

## Zod Schemas Are the Contract

All inter-package data types are derived from Zod schemas in `schemas.ts`:
```typescript
// Other packages import types like this:
import type { Server, Finding, ToolEnumeration } from "@mcp-sentinel/database";
// Never re-define types in other packages
```

When you change a schema: update `schemas.ts`, run `pnpm typecheck` — broken imports surface immediately.

## Key Enums (do not change values — they're stored in the DB)

| Enum | Values |
|------|--------|
| `SourceName` | pulsemcp, zarq, smithery, glama, npm, pypi, github, docker-hub, official-registry, awesome-mcp-servers, manual |
| `ServerCategory` | database, filesystem, api-integration, dev-tools, ai-ml, communication, cloud-infra, security, data-processing, monitoring, search, browser-web, code-execution, other |
| `Severity` | critical, high, medium, low, informational |
| `ScanStatus` | pending, running, completed, failed |
| `CapabilityTag` | reads-data, writes-data, executes-code, sends-network, accesses-filesystem, manages-credentials |

**Adding a new enum value:** add to Zod enum → add DB migration → never remove existing values (they're in historical records).

## Immutability Rules (ADR-008)
- `scan_results` → INSERT only, never UPDATE (except status field via `completeScan`)
- `findings` → INSERT only, never UPDATE
- `scores` → INSERT only, never UPDATE
- `score_history` → INSERT only, tracks every change

These tables are append-only by design. Trend data is a first-class product feature.

## Migration Workflow
```bash
pnpm db:migrate     # run pending migrations
pnpm db:seed        # load test data
pnpm db:reset       # drop all + re-migrate + re-seed (dev only)
```

Migrations live in `src/migrations/`. Number them sequentially: `001_initial.sql`, `002_add_incidents.sql`.

## What NOT to Do
- Do NOT add SQL to any other package — ever
- Do NOT UPDATE findings, scores, or scan_results (except scan status)
- Do NOT remove enum values — they may be in historical DB records
- Do NOT use raw strings for enum values in queries — use the Zod enum types
- Do NOT add application logic here — pure data access layer only
