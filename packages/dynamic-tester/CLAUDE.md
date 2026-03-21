# Package: dynamic-tester

**Purpose:** Gated dynamic tool invocation engine. Calls actual MCP server tools with canary inputs, scans outputs for injection patterns, and produces risk reports. Layer 5 capability — requires explicit consent.

## The One Rule That Cannot Be Broken

```
This package ONLY runs against servers that have explicitly opted in
via one of three consent mechanisms.

No consent → no probing. No exceptions.
```

This is ADR-007 in `agent_docs/architecture.md`. Dynamic invocation is a gated Layer 5 capability.
The `DynamicTester` returns a denied report immediately if consent is not obtained.

## Key Files
- `src/index.ts` — `DynamicTester` class (stateless, gated)
- `src/types.ts` — Zod schemas: `DynamicReport`, `ProbeResult`, `ConsentResult`, `DynamicTesterConfig`
- `src/consent.ts` — `checkConsent()` — three consent verification mechanisms
- `src/canary.ts` — `generateCanaryInput()`, `getInjectionPayloads()` — safe test input generation
- `src/output-scanner.ts` — `scanToolOutput()`, `assessOutputRisk()` — runs analyzer on tool responses
- `src/audit-log.ts` — `AuditLog` class — append-only JSONL audit trail
- `src/__tests__/` — 112 tests across 5 test files

## Consent Mechanisms (checked in order)

| Method | How It Works | Speed |
|--------|-------------|-------|
| `allowlist` | Server ID in explicit pre-approval list (CLI `--dynamic-allowlist`) | Fastest |
| `tool_declaration` | Server exposes a `mcp_sentinel_consent` tool | Requires connection |
| `wellknown` | GET `/.well-known/mcp-sentinel.json` returns `{ consent: true }` | HTTP fetch |

All consent checks are logged to the audit trail regardless of outcome.

## DynamicTester API

```typescript
const tester = new DynamicTester({ allowlist: ['server-uuid-123'] });
const report: DynamicReport = await tester.test(
  server,   // { id: string, name: string }
  endpoint, // MCP endpoint URL
  tools,    // Tool[] from connection stage
  callTool  // (name, input) => Promise<string> — provided by caller
);
```

The `callTool` callback is injected by the caller (the scan pipeline) to avoid SDK coupling.

## Execution Flow

1. **Consent check** → deny early if no consent
2. **Tool filtering** → remove blocklisted destructive tools (delete, drop, purge, etc.)
3. **Per-tool probing** → canary input → invoke → scan output → injection probes
4. **Risk aggregation** → output_injection_risk, injection_vulnerability, schema_compliance, timing_anomalies

## Safety Mechanisms

- **Blocklist**: 10 destructive tool patterns never invoked (delete, remove, drop, purge, destroy, wipe, format, shutdown, reboot, kill)
- **Max tools per server**: Default 10 — prevents excessive API usage
- **Tool timeout**: 30s default — prevents hanging connections
- **Canary inputs only**: Generated safe values (empty strings, zeros, test paths) — never real data
- **Audit trail**: Append-only JSONL at `./dynamic-test-audit.jsonl` — immutable legal record

## Pipeline Integration

Wired as **Stage 5b** in `packages/scanner/src/pipeline.ts` (after analysis, before scoring).
Enabled via `--dynamic` CLI flag on `pnpm scan`.

```bash
pnpm scan --dynamic                           # Enable dynamic testing
pnpm scan --dynamic --dynamic-allowlist=id1,id2  # With explicit allowlist
```

## Running Tests
```bash
pnpm test --filter=@mcp-sentinel/dynamic-tester
```

## What NOT to Do
- Do NOT remove or weaken consent checks — this is a legal/ethical boundary
- Do NOT modify the audit log to be mutable — append-only is a hard requirement
- Do NOT add destructive tool invocations — canary inputs only
- Do NOT invoke tools without the `callTool` callback pattern — maintains SDK isolation
- Do NOT increase `max_tools_per_server` above 25 without load testing
- Do NOT run dynamic testing outside the gated pipeline flow
