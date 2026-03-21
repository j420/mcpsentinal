# Package: risk-matrix

**Purpose:** Cross-server risk analysis. Builds a capability graph from all scored servers, detects 12 attack patterns that span multiple servers, and applies score caps. Layer 5 capability — runs after individual server scoring.

## Why This Exists

Single-server analysis (rules A–K) can miss distributed attack patterns. Example: the lethal trifecta (F1) requires private data + untrusted content + external comms **on one server**. But if Server A reads private data, Server B ingests untrusted web content, and Server C sends email — all in the same client config — the risk is identical. Pattern P01 catches this.

## Key Files
- `src/index.ts` — `RiskMatrixAnalyzer` class (analyze + score capping)
- `src/types.ts` — Zod schemas: `Capability`, `CapabilityNode`, `RiskEdge`, `RiskPattern`, `RiskMatrixReport`
- `src/graph.ts` — `buildCapabilityNode()` — classifies servers into 14 capability types
- `src/patterns.ts` — 12 cross-server risk patterns (P01–P12)
- `src/cli.ts` — `pnpm risk-matrix` CLI with DB integration
- `src/__tests__/` — 120 tests (39 graph + 81 pattern tests)

## The 12 Patterns

| ID | Name | Severity | Score Cap |
|----|------|----------|-----------|
| P01 | Cross-Config Lethal Trifecta | Critical | 40 |
| P02 | Credential Harvesting Chain | Critical | — |
| P03 | Injection Propagation Path | Critical | — |
| P04 | Shared Memory Pollution | High | — |
| P05 | Agent Config Poisoning | Critical | — |
| P06 | Data Read-Exfiltration Chain | High | — |
| P07 | Code Generation + Execution | Critical | — |
| P08 | Database Privilege Escalation | High | — |
| P09 | Email/Slack Indirect Injection | High | — |
| P10 | Web Scrape + Execute | Critical | (deduped to P03) |
| P11 | Low-Score Server in High-Trust Config | High | — |
| P12 | Multi-Hop Exfiltration | Critical | 40 |

P01 and P12 cap participating servers at score 40 (same as F1 lethal trifecta).

## Capability Graph

`buildCapabilityNode()` classifies each server into 14 capability types by matching tool names and descriptions against regex patterns:

| Capability | Examples |
|-----------|----------|
| `executes-code` | exec, run, eval, shell, python |
| `sends-network` | send, post, http, webhook, email |
| `accesses-filesystem` | read_file, write_file, mkdir |
| `web-scraping` | scrape, crawl, browse, fetch_url |
| `writes-agent-config` | write_config, .claude/, .cursor/ |
| `writes-agent-memory` | write_memory, store_memory, upsert_memory |

Classification is conservative — ambiguous tools get the more dangerous classification.

## CLI Usage

```bash
pnpm risk-matrix                    # Analyze all scored servers (limit 5000)
pnpm risk-matrix --limit=500        # Custom limit
pnpm risk-matrix --json             # JSON output for CI
pnpm risk-matrix --no-cap           # Skip score caps
pnpm risk-matrix --dry-run          # Analyze without DB writes
```

Exit code = 1 if aggregate risk is "critical".

## Pipeline Integration

Runs as a post-scoring step in `.github/workflows/scan.yml`. The risk-matrix job depends on the score job completing first.

## DB Queries Used
- `getServersWithTools(limit)` — reads servers + tools
- `upsertRiskEdges(config_id, edges)` — persists risk edges (append-only)
- `applyRiskScoreCaps(caps)` — caps `latest_score` on participating servers

## Running Tests
```bash
pnpm test --filter=@mcp-sentinel/risk-matrix
```

## What NOT to Do
- Do NOT change the P01/P12 score cap threshold (40) without product approval
- Do NOT add direct tool invocation here — this is static cross-server analysis
- Do NOT remove conservative bias from capability classification — false alarms are better than misses
- Do NOT add inline SQL — all DB access via `@mcp-sentinel/database`
- Do NOT modify score caps to be reversible without a manual review queue
