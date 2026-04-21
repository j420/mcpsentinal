# Agent Docs — CLAUDE.md

## What This Directory Contains

Deep reference documentation for the MCP Sentinel project. These docs are the authoritative source for architecture decisions, rule specifications, scoring algorithms, and product strategy. They are cross-referenced throughout package-level CLAUDE.md files and the root CLAUDE.md.

## Which Doc to Read for Which Task

| If you're working on... | Read this first |
|---|---|
| Detection rules (`rules/`, `packages/analyzer/`) | **detection-rules.md** — All 164 active rules spec (13 retired), engine handler status, threat intelligence sources, OWASP/MITRE mappings |
| Scoring (`packages/scorer/`) | **scoring-algorithm.md** — Severity weights, category sub-scores, lethal trifecta cap, OWASP coverage, score interpretation |
| Data model, pipeline stages, API contracts | **architecture.md** — Database schema, 6-stage pipeline spec, REST API contract, production topology, Railway config, GitHub Actions, failure recovery |
| Crawlers (`packages/crawler/`) | **crawler-specs.md** — Per-source crawler specifications, API endpoints, rate limits, dedup strategy |
| Product priorities, what to build / what NOT to build | **product-milestones.md** — 6-layer plan, current active layer, this week's priorities, parked items |
| Prompt execution, persona system | **prompt-execution.md** — 20 personas, run schedule, dependency chains, execution order |
| Research tracks | **research-path.md** — 8-track continuous research intelligence system |
| Competitive landscape | **competitive-intelligence.md** — Competitor analysis, differentiation points |
| Framework compliance gaps | **framework-gap-analysis.md** — Gap analysis across 8+ security frameworks |
| Technical roadmap | **technical-roadmap.md** — Future technical direction and priorities |
| Fanning out parallel sub-agents (rule migration waves, multi-rule refactors) | **sub-agent-orchestration.md** — One-rule-per-worktree protocol, allowed test commands, forbidden shared files, orchestrator cleanup-commit rules, agent briefing template |

## Doc Ownership and Update Rules

| Document | Updated by | Update trigger |
|---|---|---|
| **detection-rules.md** | P8 (Detection Rule Engineer), P1 (Threat Researcher) | New rule category added, rule spec changed, engine handler added |
| **scoring-algorithm.md** | P4 (Registry Architect) | Severity weights changed, new sub-score category, cap threshold changed. **Must stay in sync with `packages/scorer/src/scorer.ts`** |
| **architecture.md** | P4 (Registry Architect), P7 (Infrastructure Engineer) | Schema migration added, new pipeline stage, API endpoint added, deployment topology changed |
| **crawler-specs.md** | P5 (Crawler Engineer) | New crawler source added, API endpoint changed, rate limit updated |
| **product-milestones.md** | P12 (Product Strategist) | Layer completed, sprint priorities changed, items parked/resumed |
| **prompt-execution.md** | Orchestrator | Persona added/removed, schedule changed |
| **research-path.md** | P1 (Threat Researcher) | New research track, track completed |
| **competitive-intelligence.md** | P3 (Competitive Intelligence) | New competitor identified, feature comparison updated |
| **framework-gap-analysis.md** | P11 (Compliance Mapper) | New framework mapped, gap closed |
| **technical-roadmap.md** | P4 (Registry Architect) | Technical direction changed |
| **sub-agent-orchestration.md** | Orchestrator | Protocol change after a parallel-agent wave surfaces a new failure mode |

## Critical Cross-References

These pairs MUST stay in sync — changing one without the other creates inconsistencies:

| Source of truth | Must match |
|---|---|
| `scoring-algorithm.md` severity weights | `packages/scorer/src/scorer.ts` `SEVERITY_WEIGHTS` |
| `scoring-algorithm.md` category mapping | `packages/scorer/src/scorer.ts` `CATEGORY_MAP` |
| `detection-rules.md` rule definitions | `rules/*.yaml` files |
| `detection-rules.md` engine handler status | `packages/analyzer/src/engine.ts` handler implementations |
| `architecture.md` API contract | `packages/api/src/server.ts` endpoints |
| `architecture.md` data model | `packages/database/src/schemas.ts` + `migrate.ts` |
| `product-milestones.md` active layer | Root `CLAUDE.md` "Current Milestone" section |

## What NOT to Do

- Do NOT treat these docs as aspirational — they describe what IS built, not what SHOULD be built. If the code doesn't match the doc, fix whichever is wrong.
- Do NOT modify `scoring-algorithm.md` without simultaneously updating `packages/scorer/src/scorer.ts` (and vice versa).
- Do NOT add a new rule category to `detection-rules.md` without adding it to the scorer's `CATEGORY_MAP`.
- Do NOT reference doc versions — these are living documents, not versioned specs.
