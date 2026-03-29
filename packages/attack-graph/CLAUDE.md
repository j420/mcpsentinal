# Package: attack-graph

**Purpose:** Multi-step kill chain synthesis across MCP server configurations. Consumes risk-matrix edges (P01-P12) and capability graph nodes, synthesizes ordered attack chains with exploitability scoring, narratives, and actionable mitigations.

## The Moat

Nobody else computes: *"Given these 5 MCP servers in your Claude Desktop config, here are the 3 ways an attacker can exfiltrate your data without you noticing."*

Single-server scanning (packages/analyzer) finds individual vulnerabilities.
Cross-server edge detection (packages/risk-matrix) finds dangerous capability pairs.
**This package synthesizes multi-step attack narratives from those edges** — the full kill chain an attacker would execute.

## Architecture

```
risk-matrix edges (P01-P12) ──→ AttackGraphEngine.analyze()
capability graph nodes      ──→   │
                                  ├─ prerequisite check (patterns + edge types)
                                  ├─ role assignment (capabilities → roles)
                                  ├─ combination generation (distinct servers)
                                  ├─ edge verification (risk-matrix connects steps)
                                  ├─ exploitability scoring (7 factors)
                                  ├─ deduplication (same servers + template)
                                  └─ narrative + mitigation generation
                                      │
                                      ▼
                                AttackGraphReport
```

## Kill Chain Templates (KC01-KC07)

| ID | Name | Precedent | Min Servers |
|----|------|-----------|-------------|
| KC01 | Indirect Injection → Data Exfiltration | Claude Desktop 2024-Q4 | 3 |
| KC02 | Config Poisoning → RCE | CVE-2025-54135 (.cursorrules) | 2 |
| KC03 | Credential Harvesting Chain | Wiz Research (2025) | 2 |
| KC04 | Memory Poisoning Persistence | Invariant Labs (Jan 2026) | 3 |
| KC05 | Code Generation → Execution | Trail of Bits (Feb 2026) | 3 |
| KC06 | Multi-Hop Data Exfiltration | DNS exfiltration research | 3 |
| KC07 | Database Privilege Escalation → Theft | DB privesc via MCP (2025) | 2 |

Every template has a real-world precedent. No theoretical chains.

## 7-Factor Exploitability Scoring

| Factor | Weight | What It Measures |
|--------|--------|-----------------|
| hop_count | 0.15 | Fewer hops = easier to exploit |
| capability_confidence | 0.20 | How confidently we classified capabilities |
| server_score_weakness | 0.15 | Weakest server in the chain |
| real_world_precedent | 0.15 | CVE/research backing |
| injection_gateway_present | 0.10 | Confirmed entry point exists |
| supporting_findings | 0.10 | Single-server findings that strengthen chain |
| edge_severity | 0.15 | Severity of connecting edges |

Rating: ≥0.75 critical, ≥0.55 high, ≥0.35 medium, <0.35 low.

## Key Files

| File | Purpose |
|------|---------|
| `src/types.ts` | All type definitions (AttackChain, ExploitabilityScore, KillChainTemplate, etc.) |
| `src/kill-chains.ts` | KC01-KC07 template definitions + prerequisite checkers |
| `src/scoring.ts` | 7-factor exploitability computation |
| `src/engine.ts` | AttackGraphEngine — template-driven chain synthesis |
| `src/narrative.ts` | Deterministic narrative + mitigation generation |
| `src/index.ts` | Package exports |
| `src/cli.ts` | CLI entry point — DB-integrated chain synthesis |
| `src/__tests__/scoring.test.ts` | 63 scoring tests |
| `src/__tests__/engine.test.ts` | 74 engine tests (7 KC × 8 + engine-wide + narrative coverage) |
| `src/__tests__/narrative.test.ts` | 13 narrative + mitigation tests |
| `src/__tests__/fixtures/` | Reusable node + edge factories |

## Database (in packages/database)

- Migration: `010_attack_chains` — append-only table (ADR-008)
- Queries: `insertAttackChains()`, `getAttackChainsForConfig()`, `getChainHistory()`, `getAttackChainsForServer()`, `getFindingRuleIdsByServerIds()`
- Schema: `AttackChainSchema`, `AttackChainInputSchema`

## Commands

```bash
pnpm test --filter=@mcp-sentinel/attack-graph   # Run all 150 tests
pnpm --filter=@mcp-sentinel/attack-graph typecheck  # TypeScript type checking

# CLI (database-integrated)
pnpm attack-graph                    # Analyse all scored servers (up to 5000)
pnpm attack-graph --limit=500        # Limit server set size
pnpm attack-graph --json             # JSON output for CI
pnpm attack-graph --dry-run          # Analyse without DB writes
pnpm attack-graph --with-findings    # Include per-server findings for scoring boost
```

## Pipeline Integration

Runs as a post-risk-matrix step in `.github/workflows/scan.yml`:
1. Loads scored servers from DB via `getServersWithTools()`
2. Runs `RiskMatrixAnalyzer` inline to get fresh edges + capability nodes
3. Optionally loads per-server findings for scoring boost (`--with-findings`)
4. Runs `AttackGraphEngine.analyze()` to synthesize kill chains
5. Persists chains via `insertAttackChains()` (append-only, ADR-008)

Exit code = 1 if aggregate risk is "critical".

## What NOT To Do

- Do NOT add LLM calls — all narrative generation is deterministic (ADR-006)
- Do NOT add generic pathfinding — every chain matches a specific template
- Do NOT invoke MCP server tools — we only analyze metadata (ADR-007)
- Do NOT UPDATE attack_chains rows — append-only (ADR-008)
- Do NOT add a template without a real-world precedent (CVE or published research)
