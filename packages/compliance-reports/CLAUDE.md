# Package: compliance-reports

**Purpose:** Turn scan findings into signed, regulator-facing compliance reports for 7 frameworks (EU AI Act, ISO 27001, OWASP MCP, OWASP ASI, CoSAI, MAESTRO, MITRE ATLAS). Phase 5 of the v2 migration plan.

This is the **data-model + attestation backbone** for Phase 5. Renderers (HTML/JSON/PDF), kill-chain integration, and HTTP endpoints plug into the interfaces exported here. This package does NOT render PDFs, does NOT call the database, and does NOT own HTTP routes — it's pure assembly + cryptographic attestation.

## Key Files
- `src/types.ts` — `ComplianceReport`, `SignedComplianceReport`, `ControlResult`, `KillChainNarrative` — the stable wire contract
- `src/canonicalize.ts` — RFC 8785 JSON canonicalization (deterministic byte-for-byte encoding)
- `src/attestation.ts` — HMAC-SHA256 sign/verify built on Node's `crypto` (no extra deps)
- `src/frameworks/` — one file per framework (`eu_ai_act.ts`, `iso_27001.ts`, …) + `index.ts` aggregator
- `src/build-report.ts` — mechanical status derivation: findings × framework controls → `ComplianceReport`
- `src/render/types.ts` — renderer contract (Agent 2 implements)
- `src/badges/types.ts` — badge-renderer contract (Agent 4 implements)
- `src/index.ts` — public exports

## Architecture Decisions

- **RFC 8785 canonicalization before signing.** The signed bytes must be reproducible by any regulator using any RFC-compliant JSON library. We use UTF-16 code-unit key sorting, ECMAScript 2019 number serialization, and zero whitespace.
- **HMAC-SHA256 is the v1 attestation scheme.** Node's built-in `crypto` only. No crypto npm deps. Dev fallback key logs a warning. Production key comes from `COMPLIANCE_SIGNING_KEY` env var with public `COMPLIANCE_SIGNING_KEY_ID`.
- **Status derivation is mechanical, not interpretive.** `met`/`unmet`/`partial`/`not_applicable` is computed from assessor-rule findings + `unmet_threshold` severity — no LLM judgement at this layer (ADR-009 scoping).
- **Honest gaps over invented coverage.** Controls with no assessor rule are marked `not_applicable` via empty `assessor_rule_ids: []` and a `// NO ASSESSOR RULE` comment. See `src/frameworks/*.ts` for documented gaps.

## What NOT to Do

- Do NOT render PDFs/HTML here — register a `ComplianceReportRenderer` instead (Agent 2 scope)
- Do NOT extend HTTP routes here — `packages/api` consumes these types (Agent 4 scope)
- Do NOT add crypto npm deps — Node `crypto` only
- Do NOT invent framework control mappings; honest gaps are required
- Do NOT add LLM calls — ADR-009 scopes the exception to `packages/compliance-agents/` only
- Do NOT confuse this with `packages/reports/` — that's ecosystem aggregate, this is per-server-per-framework

## Running Tests

```bash
pnpm --filter=@mcp-sentinel/compliance-reports typecheck
pnpm --filter=@mcp-sentinel/compliance-reports test
```
