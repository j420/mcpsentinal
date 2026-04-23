# Package: api

**Purpose:** Public REST API. Express server exposing registry data. Read-only for public consumers — no auth, no writes.

## Key Files
- `src/server.ts` — Express app, all route handlers (incl. compliance-report route registration)
- `src/badge.ts` — SVG security badge generator (score-based)
- `src/compliance-report-routes.ts` — Phase 5 signed compliance report handlers (HTML/PDF/JSON + per-framework badge SVG); HMAC-SHA256 attestation via `@mcp-sentinel/compliance-reports`
- `src/index.ts` — server entry point

## Endpoints (treat as stable public API)

```
GET /api/v1/servers                                       → paginated server list with filtering
GET /api/v1/servers/:slug                                 → single server detail
GET /api/v1/servers/:slug/findings                        → findings for a server
GET /api/v1/servers/:slug/history                         → score history
GET /api/v1/servers/:slug/badge.svg                       → SVG security badge (score-based)
GET /api/v1/ecosystem/stats                               → aggregate ecosystem statistics

# Phase 5 — regulator-facing signed compliance reports (all HMAC-SHA256 attested)
GET /api/v1/servers/:slug/compliance/:framework.json      → signed SignedComplianceReport envelope (JSON)
GET /api/v1/servers/:slug/compliance/:framework.html      → regulator-grade HTML render (self-contained)
GET /api/v1/servers/:slug/compliance/:framework.pdf       → deterministic PDF render (pdfkit, regulator-filable)
GET /api/v1/servers/:slug/compliance/:framework/badge.svg → per-framework compliance badge SVG

GET /health                                               → health check
```

`:framework` must be one of: `eu_ai_act`, `iso_27001`, `owasp_mcp`, `owasp_asi`, `cosai_mcp`, `maestro`, `mitre_atlas`. Unknown id → 404 `{ error: "unknown_framework", valid: [...] }`.

Signed-compliance responses set attestation headers on every 200:
- `X-MCP-Sentinel-Signature`, `X-MCP-Sentinel-Key-Id`, `X-MCP-Sentinel-Signed-At`
- `X-MCP-Sentinel-Algorithm: HMAC-SHA256`
- `X-MCP-Sentinel-Canonicalization: RFC8785`
- `X-MCP-Sentinel-Warning: dev-key-in-use` (only when `COMPLIANCE_SIGNING_KEY` env var is unset — MUST be set in Railway before public launch)

Once shipped, endpoint URLs and response shapes are **public contracts**.
Breaking changes require a version bump (v1 → v2).

## Validation Rules
- All query parameters MUST be validated with Zod before use
- All `:slug` / `:id` path params MUST be validated before DB lookup
- Invalid input → 400 with structured error, never 500

```typescript
// Pattern to follow — always validate first:
const params = QuerySchema.safeParse(req.query);
if (!params.success) return res.status(400).json({ error: params.error.issues });
```

## No Business Logic in Routes
Route handlers should be thin:
1. Validate input with Zod
2. Call one function from `@mcp-sentinel/database`
3. Return the result

If you need to transform data, put it in a helper or in the database queries layer.

## What NOT to Do
- Do NOT add authentication endpoints — public read-only for now (see CLAUDE.md)
- Do NOT add write endpoints for external users — scanning is internal only
- Do NOT add inline SQL — import from `@mcp-sentinel/database`
- Do NOT change response shapes of existing endpoints without a version bump
- Do NOT add LLM calls — deterministic only (ADR-006)
- Do NOT add rate limiting until public launch (track in technical debt register)
