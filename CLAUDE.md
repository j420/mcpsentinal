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
│   ├── analyzer/                ← Analysis: runs 76 detection rules, produces findings (has CLAUDE.md)
│   ├── scorer/                  ← Scoring: computes composite scores from findings (has CLAUDE.md)
│   ├── database/                ← PostgreSQL schema, migrations, queries — ALL SQL lives here (has CLAUDE.md)
│   ├── api/                     ← Public REST API (has CLAUDE.md)
│   ├── web/                     ← Next.js registry website (has CLAUDE.md)
│   └── cli/                     ← npx mcp-sentinel CLI tool (has CLAUDE.md)
├── docs/
│   └── runbooks/                ← Operational runbooks: add-new-rule, new-cve-response, full-crawl
├── tools/
│   └── scripts/                 ← validate-rules.sh and operational scripts
├── rules/                       ← Detection rule definitions (YAML) — 76 rules across A–I
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
2. **Rules are data, not code.** Detection rules are YAML definitions. The analyzer interprets them. Adding a rule should never require changing engine code.
3. **No LLM in v1.** All detection is deterministic (regex, AST, schema validation, CVE lookup). LLM classification is v1.1 — only added where rules demonstrably fail.
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
## Working with Detection Rules
Read @agent_docs/detection-rules.md before touching rules/ or packages/analyzer/.
Rules follow this structure:
```yaml
id: C1
name: Command Injection
category: code-analysis
severity: critical
owasp: MCP03
mitre: AML.T0054
detect:
  type: regex
  patterns:
    - "exec\\s*\\("
    - "execSync\\s*\\("
    - "child_process"
  context: source_code
  exclude_patterns:
    - "// safe: sanitized input"
remediation: "Replace exec() with execFile() and validate all inputs against an allowlist."
test_cases:
  true_positive:
    - { file: "fixtures/vuln-exec.ts", expected: true }
    - { file: "fixtures/vuln-subprocess.py", expected: true }
  true_negative:
    - { file: "fixtures/safe-execfile.ts", expected: false }
    - { file: "fixtures/safe-sanitized.ts", expected: false }
```
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
## Current Milestone
Read @agent_docs/product-milestones.md for the current sprint focus.
**Active layer:** Check the milestones doc. Only work on the active layer unless explicitly told otherwise. Each layer depends on the one below it. Don't skip ahead.
## Meta-Prompt Execution (For the Orchestrator)
Read @agent_docs/prompt-execution.md for the complete prompt execution workflow with all 20 personas, their run schedule, and dependency chain.
## When Compacting
When compacting, always preserve: the current milestone and active layer, the list of all modified files in this session, any failing tests or unresolved issues, and the pipeline stage being worked on.
