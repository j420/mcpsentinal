# MCP Sentinel — The World's Most Comprehensive MCP Security Intelligence Registry
## What This Is
MCP Sentinel scans every public MCP server in existence, measures their security posture, and publishes the results as a searchable registry. We are not a gateway. We are not a scanner tool. We are the security intelligence layer that sits upstream of every gateway, every registry, and every deployment decision in the MCP ecosystem. The data IS the product.
**Our unique insight:** Nobody has actually measured what's happening across the MCP ecosystem. Everyone builds from theory. We build from data.
## Tech Stack
- **Language:** TypeScript (Node.js) — required for MCP SDK compatibility
- **Database:** PostgreSQL with full-text search
- **MCP SDK:** `@modelcontextprotocol/sdk` for server connection and tool enumeration
- **Web:** Next.js (public registry website)
- **CLI:** `npx mcp-sentinel` (published to npm)
- **Testing:** Vitest for unit tests, Playwright for E2E
- **Formatting:** Prettier + ESLint (Biome config)
## Project Structure
```
mcp-sentinel/
├── CLAUDE.md                    ← You are here
├── agent_docs/                  ← IMPORTANT: Read relevant docs before working on any module
│   ├── architecture.md          ← Data model, pipeline stages, API contracts
│   ├── detection-rules.md       ← All security detection rules with test cases
│   ├── crawler-specs.md         ← Per-source crawler specifications
│   ├── scoring-algorithm.md     ← How composite scores are calculated
│   ├── prompt-execution.md      ← Meta-prompt execution order and workflow
│   ├── research-path.md         ← Continuous 8-track research intelligence system
│   └── product-milestones.md    ← Current milestone, what to build, what NOT to build
├── .claude/
│   ├── settings.json            ← Claude Code permissions and hook configuration
│   ├── hooks/                   ← Enforced guardrails (run automatically on edits)
│   │   ├── post-edit/           ← validate-rule-yaml.sh, no-inline-sql.sh
│   │   ├── pre-tool-use/        ← block-mcp-invocation.sh
│   │   └── stop/                ← typecheck-reminder.sh
│   └── skills/                  ← Reusable step-by-step workflows
│       ├── add-detection-rule/  ← SKILL.md: 6-step rule addition checklist
│       ├── add-crawler-source/  ← SKILL.md: crawler implementation guide
│       └── release/             ← SKILL.md: pre-release quality checklist
├── packages/
│   ├── crawler/                 ← Discovery: finds MCP servers across 7+ sources (each has CLAUDE.md)
│   ├── connector/               ← Connection: MCP SDK wrapper — initialize + tools/list ONLY (has CLAUDE.md)
│   ├── analyzer/                ← Analysis: runs 177 detection rules, produces findings (has CLAUDE.md)
│   ├── scorer/                  ← Scoring: computes composite scores from findings (has CLAUDE.md)
│   ├── database/                ← PostgreSQL schema, migrations, queries — ALL SQL lives here (has CLAUDE.md)
│   ├── api/                     ← Public REST API (has CLAUDE.md)
│   ├── web/                     ← Next.js registry website (has CLAUDE.md)
│   ├── cli/                     ← npx mcp-sentinel CLI tool (has CLAUDE.md)
│   └── mcp-sentinel-scanner/    ← MCP server that exposes scanning as tools (has CLAUDE.md)
├── docs/
│   └── runbooks/                ← Operational runbooks: add-new-rule, new-cve-response, full-crawl
├── tools/
│   └── scripts/                 ← validate-rules.sh and operational scripts
├── rules/                       ← Detection rule metadata (YAML) — 177 rules across A–Q (detection logic in TypeScript)
├── tests/                       ← Integration and E2E tests
└── data/                        ← Seed data, test fixtures
```
## Commands
```bash
# Development
pnpm install                     # Install all dependencies
pnpm dev                         # Run all packages in dev mode
pnpm dev --filter=crawler        # Run single package
# Database
pnpm db:migrate                  # Run migrations
pnpm db:seed                     # Seed test data
pnpm db:reset                    # Reset and re-seed
# Crawling & Scanning
pnpm crawl                       # Run all crawlers
pnpm crawl:pulsemcp              # Run single source crawler
pnpm scan                        # Scan all unscanned servers
pnpm scan --server=<id>          # Scan specific server
pnpm score                       # Recompute all scores
# Testing
pnpm test                        # Run all tests
pnpm test --filter=analyzer      # Test single package
pnpm typecheck                   # TypeScript type checking
pnpm lint                        # ESLint + Prettier check
# CLI (local development)
pnpm cli check                   # Test CLI against local MCP configs
pnpm cli check --json            # JSON output for CI
# Build & Deploy
pnpm build                       # Build all packages
pnpm deploy:web                  # Deploy registry website
```
## Architecture Principles
1. **Pipeline, not monolith.** Data flows: Discovery → Connection → Analysis → Scoring → Publication. Each stage is a separate package with a clear contract.
2. **Rules are metadata + TypeScript.** YAML files define rule metadata only (id, severity, OWASP/MITRE mappings, test cases). ALL 177 detection rules are implemented as TypedRules in TypeScript inside `packages/analyzer/src/rules/implementations/`. Zero YAML regex patterns remain. Detection uses AST taint analysis, capability graph algorithms, entropy-based secret detection, Levenshtein similarity, and structural parsing.
3. **No LLM in v1.** All detection is deterministic (AST taint, capability graph, entropy, schema inference, linguistic scoring). LLM classification is v1.1 — only added where a deterministic rule demonstrably fails.
4. **Collect everything, judge later.** Crawlers store raw metadata. Analysis is a separate pass. Never discard data because you don't have a rule for it yet.
5. **History by default.** Every scan result is immutable. Scores change over time. The history table tracks every change. Trends are a first-class feature.
## Coding Rules
- IMPORTANT: Every function that produces a security finding MUST include the rule_id, evidence (what triggered it), and remediation (how to fix it). Findings without evidence are useless.
- IMPORTANT: Every crawler MUST log: source, servers_found, new_unique, duplicates, errors, elapsed_time. We track yield per source obsessively.
- IMPORTANT: Never invoke MCP server tools during scanning. We only call `initialize` and `tools/list`. Dynamic invocation is a separate, gated capability (see @agent_docs/detection-rules.md Section F).
- Use Zod for all API input validation and type inference.
- Use structured logging (pino) with correlation IDs across pipeline stages.
- Database queries go in `packages/database/queries/` — never inline SQL in other packages.
- All detection rules get test cases: minimum 2 true positives, 2 true negatives per rule.
- 882 tests across 14 test files (833 analyzer + 49 red-team), 30+ per category.
## Working with Detection Rules
Read @agent_docs/detection-rules.md before touching rules/ or packages/analyzer/.

**ALL 177 rules are TypedRule implementations.** Zero YAML regex remains. YAML files contain metadata only (`detect.type: typed`). All detection logic is in TypeScript.

### Rule YAML structure (metadata only):
```yaml
id: C1
name: Command Injection
category: code-analysis
severity: critical
owasp: MCP03
mitre: AML.T0054
detect:
  type: typed
remediation: "Replace exec() with execFile() and validate all inputs against an allowlist."
enabled: true
test_cases:
  true_positive:
    - { description: "exec with user input", expected: true }
  true_negative:
    - { description: "execFile with array args", expected: false }
```

### TypedRule implementation (detection logic):
Detection logic lives in `packages/analyzer/src/rules/implementations/` across 17 detector files:

| Detector | Rules | Analysis Technique |
|----------|-------|--------------------|
| `c1-command-injection.ts` | C1 | AST taint (source→sink with sanitizer detection) |
| `tainted-execution-detector.ts` | C4, C12, C13, C16, K9, J2 | AST taint + lightweight taint |
| `code-security-deep-detector.ts` | C2, C5, C10, C14 | AST taint + Shannon entropy + context-aware |
| `code-remaining-detector.ts` | C3, C6-C9, C11, C15 | AST taint + structural |
| `description-schema-detector.ts` | A1-A5, A8, B1-B7 | Multi-signal linguistic scoring + structural |
| `a6-unicode-homoglyph.ts` | A6, A7 | Unicode codepoint analysis |
| `a9-encoded-instructions.ts` | A9 | Base64/hex/URL encoding detection |
| `d3-typosquatting.ts` | D3 | Damerau-Levenshtein similarity |
| `dependency-behavioral-detector.ts` | D1-D7, E1-E4 | Dependency analysis + behavioral checks |
| `f1-lethal-trifecta.ts` | F1, F2, F3, F6, F7 | Capability graph + schema inference |
| `ecosystem-adversarial-detector.ts` | F4, F5, G6, H1, H3 | Levenshtein + OAuth pattern + historical diff |
| `ai-manipulation-detector.ts` | G1, G2, G3, G5, H2 | Capability graph + linguistic patterns |
| `g4-context-saturation.ts` | G4 | Context window analysis |
| `cross-tool-risk-detector.ts` | I1, I2, I13, I16 | Capability graph + schema inference |
| `config-poisoning-detector.ts` | J1, L4, L11, Q4 | AST taint + structural config parsing |
| `secret-exfil-detector.ts` | L9, K2, G7 | AST taint + entropy |
| `supply-chain-detector.ts` | L5, L12, L14, K10 | JSON structural parsing |
| `infrastructure-detector.ts` | P1-P7 | Dockerfile/k8s structural parsing |
| `advanced-supply-chain-detector.ts` | L1, L2, L6, L7, L13, K3, K5, K8 | Import resolution + AST taint |
| `protocol-ai-runtime-detector.ts` | M1, M3, M6, M9, N4-N15 | Protocol structural analysis |
| `data-privacy-cross-ecosystem-detector.ts` | O1-O9, Q1-Q13 | AST taint + structural |
| `protocol-surface-remaining-detector.ts` | I2-I15, J3-J7 | Protocol structural analysis |
| `compliance-remaining-detector.ts` | K1-K20, L3-L15, M2-M8, N1-N10, O4-O10, P8-P10, Q10-Q15 | Factory-built structural rules |

### Adding a new rule:
1. Create YAML in `rules/` with metadata (id, severity, owasp, remediation, test_cases)
2. Set `detect.type: typed`
3. Implement `TypedRule` in `packages/analyzer/src/rules/implementations/`
4. Call `registerTypedRule(new YourRule())` at module level
5. Add import to `packages/analyzer/src/rules/index.ts`
6. Add tests to `packages/analyzer/__tests__/`
7. **Never add YAML regex patterns** — all detection must be TypeScript
## Working with the Scoring Algorithm
Read @agent_docs/scoring-algorithm.md before touching packages/scorer/.
Score = 100 minus weighted penalty deductions. Never returns below 0 or above 100.
## Git Workflow
- Branch naming: `feat/`, `fix/`, `rule/`, `crawler/` prefixes
- Commits: conventional commits (`feat:`, `fix:`, `rule:`, `chore:`)
- PRs: require passing tests + typecheck
- Never commit API keys, tokens, or credentials. Use `.env.local`.
## What NOT To Do
- Do NOT build user authentication yet. The registry is public read-only for now.
- Do NOT build a payment system. Monetization is post-seed.
- Do NOT add LLM API calls. All analysis is deterministic in v1.
- Do NOT optimize for performance before we have 10,000 servers. Correctness first.
- Do NOT modify the scoring weights without updating @agent_docs/scoring-algorithm.md.

## Production Deployment

**There are no always-on workers.** The pipeline runs entirely on GitHub Actions runners.
**Full topology doc:** @agent_docs/architecture.md → "Production Architecture" section.

### Services

| Service | Platform | Role | Auto-deploy |
|---------|----------|------|-------------|
| PostgreSQL | Railway (managed) | Primary database | N/A |
| API (`packages/api`) | Railway | REST API + badge SVG | `main` push |
| Web (`packages/web`) | Railway or Vercel | Next.js public registry | `main` push |
| CLI (`packages/cli`) | npm registry | `npx mcp-sentinel` | manual publish |

### GitHub Actions Workflows

| Workflow | Schedule | What it does |
|----------|----------|-------------|
| `ci.yml` | Every PR + push to main | typecheck → test → build |
| `crawl.yml` | Sundays 02:00 UTC + manual | 6 crawlers in parallel → DB |
| `scan.yml` | Daily 04:00 UTC + after crawl + manual | scan → score pipeline |

**Auto-chain:** `crawl.yml` completion triggers `scan.yml` via `workflow_run`.
**Concurrency:** `scan.yml` queues a second trigger rather than cancelling a running scan.

### Required GitHub Actions Secrets

| Secret | Used by | Notes |
|--------|---------|-------|
| `DATABASE_URL` | crawl.yml, scan.yml | Railway PostgreSQL URL |
| `SMITHERY_API_KEY` | crawl.yml | Smithery registry API key |
| `GITHUB_TOKEN` | scan.yml | Auto-injected — no setup needed |

### Scan Modes (scan.yml `workflow_dispatch`)

| Mode | When to use |
|------|-------------|
| `incremental` | Default daily runs — only unscanned servers |
| `rescan-failed` | After fixing a scanner bug |
| `full` | After adding new detection rules — rescans everything |
| `--server=<id>` | Debug a specific server |

### Recovery Quick-Reference

| Problem | Fix |
|---------|-----|
| Scan timeout | Re-run scan.yml with `incremental` — already-scanned servers skip |
| Score stale | Run `pnpm score` locally with `DATABASE_URL` |
| Crawl partial failure | Re-run crawl.yml with the specific failing source |
| DB migration failed | Fix SQL, re-run workflow (crawl/scan won't run until migrate passes) |

## Known Issues (P0 — Fix Before Merging to Main)

### [RESOLVED] H2 Rule Is Completely Blind
Fixed: `MCPConnector.enumerate()` now captures `serverInfo.version` and `instructions` via
`client.getServerVersion()` and `client.getInstructions()` after the initialize handshake.
`ToolEnumerationSchema` extended with `server_version` + `server_instructions`.
Pipeline populates `initialize_metadata` from the enumeration result. H2 rule now has data.

### [RESOLVED] Wrong Spec Versions in detection-rules.md
Fixed: `agent_docs/detection-rules.md` updated — `instructions` field correctly attributed to
`2024-11-05` spec. All `2025-11-05` references corrected to `2025-03-26`.

### [RESOLVED] All 177 Rules Migrated from YAML Regex to TypedRules
All 177 detection rules now have TypeScript TypedRule implementations using AST taint analysis,
capability graph algorithms, Shannon entropy, structural parsing, and linguistic scoring.
Zero YAML regex patterns remain. YAML files contain metadata only (`detect.type: typed`).
Engine auto-registers all TypedRules via side-effect import in `engine.ts`.
882 tests passing (833 analyzer + 49 red-team). npm package `mcp-sentinel-scanner@0.2.0` published.

### [RESOLVED] CI Workflow Invalid — paths + paths-ignore conflict
Fixed: Removed `paths-ignore` blocks from `.github/workflows/ci.yml`. GitHub Actions does not
allow both `paths` and `paths-ignore` on the same event trigger.

### [RESOLVED] Railway "Failed to find Server Action" on Redeploy
Fixed: Added `generateBuildId()` to `next.config.ts` (unique build ID per deploy) and
`RAILWAY_GIT_COMMIT_SHA` build ARG to Dockerfile (busts Docker layer cache).
## Current Milestone
Read @agent_docs/product-milestones.md for the current sprint focus.
**Active layer:** Check the milestones doc. Only work on the active layer unless explicitly told otherwise. Each layer depends on the one below it. Don't skip ahead.
## Meta-Prompt Execution (For the Orchestrator)
Read @agent_docs/prompt-execution.md for the complete prompt execution workflow with all 20 personas, their run schedule, and dependency chain.
## When Compacting
When compacting, always preserve: the current milestone and active layer, the list of all modified files in this session, any failing tests or unresolved issues, and the pipeline stage being worked on.
