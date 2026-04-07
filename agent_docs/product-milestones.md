# MCP Sentinel — Product Milestones
## P12 Product Strategist Output — v1.1

_Last updated: 2026-03-25_

### Active Layer: Layer 3 (Public Interface) — polish & SEO

### 6-Layer Registry Plan

| Layer | Name | Status | Dependencies |
|-------|------|--------|-------------|
| 1 | Data Foundation | **COMPLETE** | None |
| 2 | Security Intelligence | **COMPLETE** | Layer 1 |
| 3 | Public Interface | **ACTIVE** — pages built, needs SEO polish | Layer 2 |
| 4 | Developer Tools | **COMPLETE** | Layer 3 |
| 5 | Advanced Detection | **COMPLETE** | Layer 4 |
| 6 | Compliance & Enterprise | Pending | Layer 5 |

---

### Layer 1: Data Foundation — COMPLETE

**Goal:** Crawl and store MCP servers from 5+ sources, deduplicated into a single database.

**Deliverables:**
- [x] Database schema (PostgreSQL with FTS) — `packages/database/src/` (schemas.ts, queries.ts, migrate.ts, seed.ts, reset.ts)
- [x] Crawler for npm — `packages/crawler/src/sources/npm.ts`
- [x] Crawler for GitHub — `packages/crawler/src/sources/github.ts`
- [x] Crawler for PyPI — `packages/crawler/src/sources/pypi.ts`
- [x] Crawler for PulseMCP — `packages/crawler/src/sources/pulsemcp.ts`
- [x] Crawler for Smithery — `packages/crawler/src/sources/smithery.ts`
- [x] Crawler for Official MCP Registry — `packages/crawler/src/sources/mcpregistry.ts`
- [x] Crawler for modelcontextprotocol GitHub repo — `packages/crawler/src/sources/modelcontextprotocol-repo.ts`
- [x] Crawler orchestrator — `packages/crawler/src/orchestrator.ts`
- [x] Crawler CLI — `packages/crawler/src/cli.ts`
- [x] GitHub Actions crawl workflow — `.github/workflows/crawl.yml` (Sundays 02:00 UTC + manual dispatch, 6 crawlers in parallel)
- [~] Crawler for MCP Server Cards (.well-known/mcp) — PARKED: resume when crawler expansion resumes
- [~] Crawler for Glama — PARKED: SourceName enum exists, implement when expanding sources
- [~] Crawler for awesome-mcp-servers — PARKED: SourceName enum exists, implement when expanding sources
- [~] Deduplication pipeline — PARKED: only worth building once crawl volume justifies it (10k+ servers)
- [x] First full crawl: target 10,000+ unique servers

**Status:** Complete. All 7 crawlers implemented, tested, and first live crawl executed.

**Success Criteria:** 10,000 unique servers in the database with >80% having at least one identifier (GitHub URL or package name).
_Note: Ecosystem grew to 10,000+ active servers by December 2025 (AAIF announcement). Original 5,000 target is outdated._

---

### Layer 2: Security Intelligence — COMPLETE

**Goal:** Run detection rules against every server and produce scored results.

**Deliverables:**
- [x] 164 active detection rules across 17 categories (A-Q) — `rules/` directory (177 YAML files, 13 retired)
  - A: Description Analysis (9), B: Schema Analysis (7), C: Code Analysis (16), D: Dependency Analysis (7)
  - E: Behavioral Analysis (4), F: Ecosystem Context (7), G: Adversarial AI (7), H: 2026 Attack Surface (3)
  - I: Protocol Surface (16), J: 2026 Threat Intelligence (7), K: Compliance & Governance (20)
  - L: Supply Chain Advanced (15), M: AI Runtime Exploitation (8, 1 retired), N: Protocol Edge Cases (15)
  - O: Data Privacy Attacks (6, 4 retired), P: Infrastructure Runtime (10), Q: Cross-Ecosystem Emergent (7, 8 retired)
- [x] Analysis engine — `packages/analyzer/src/engine.ts` (specialized engines + 164 active TypedRule dispatch)
- [x] **ALL rules migrated to TypedRules** — AST taint, capability graph, entropy, structural parsing (23 detector files, ~13K lines). 13 rules subsequently retired due to high FP rates; 164 active.
- [x] 1051 tests passing (1002 analyzer + 49 red-team), 30+ per category across 16 test files
- [x] Rule loader — `packages/analyzer/src/rule-loader.ts` (YAML metadata interpretation)
- [x] npm package published: `mcp-sentinel-scanner@0.2.0` with all TypedRules bundled
- [x] Tool fingerprinting — `packages/analyzer/src/tool-fingerprint.ts`
- [x] Scoring algorithm — `packages/scorer/src/scorer.ts` (100 - penalties, lethal trifecta cap, sub-scores per category)
- [x] MCP Connector — `packages/connector/src/connector.ts` (initialize + tools/list only, per ADR-007)
- [x] Source code fetcher — `packages/scanner/src/fetcher.ts` (GitHub raw content)
- [x] Dependency auditor — `packages/scanner/src/auditor.ts` (OSV API integration)
- [x] Full scan pipeline — `packages/scanner/src/pipeline.ts` (7 stages with concurrency + stage isolation)
- [x] Scanner CLI — `packages/scanner/src/cli.ts` (modes: incremental, rescan-failed, full, --server, --dynamic)
- [x] **P0 BUG FIXED:** initialize_metadata pipeline — H2 rule now receives live data via `client.getServerVersion()` + `client.getInstructions()`
- [x] GitHub Actions scan workflow — `.github/workflows/scan.yml` (Daily 04:00 UTC + after crawl + manual dispatch)
- [x] Accuracy auditing workflow — `.github/workflows/accuracy.yml` (precision/recall metrics)
- [ ] Scan all 10,000 servers — requires Layer 1 crawl data in production database

**Status:** Code-complete. All 164 active rules authored and tested (13 retired due to high FP rates), engine tested, pipeline integrated. Awaiting first live scan against crawled server data.

**Success Criteria:** 10,000 servers scanned, findings distribution matches expectations (most servers should have some findings).

---

### Layer 3: Public Interface — ACTIVE (polish & SEO remaining)

**Goal:** Searchable public registry website with server detail pages.

**Deliverables:**
- [x] REST API — `packages/api/src/server.ts` (all CRUD endpoints: /servers, /servers/:slug, /findings, /score, /history, /badge.svg, /ecosystem/stats, /ecosystem/categories)
- [x] Badge generator — `packages/api/src/badge.ts` (SVG)
- [x] Next.js website with search — `packages/web/src/app/page.tsx` (home), `servers/page.tsx` (listing)
- [x] Server detail page — `packages/web/src/app/servers/[slug]/page.tsx` (score, findings, tools, history)
- [x] Category browse pages — `packages/web/src/app/categories/page.tsx`, `categories/[category]/page.tsx`
- [x] Ecosystem dashboard — `packages/web/src/app/dashboard/page.tsx`
- [x] About page — `packages/web/src/app/about/page.tsx`
- [x] Taxonomy/rules reference — `packages/web/src/app/taxonomy/page.tsx`
- [ ] SEO optimization (meta tags, structured data, Open Graph)
- [ ] Content polish and final UI review

**Status:** All pages built and functional. SEO and content polish remaining.

**Success Criteria:** Publicly accessible at mcp-sentinel.com, indexed by Google.

---

### Layer 4: Developer Tools — COMPLETE

**Goal:** CLI tool and CI/CD integration for developers to check their MCP configs.

**Deliverables:**
- [x] CLI tool — `packages/cli/src/cli.ts` (npx mcp-sentinel check, comprehensive implementation)
- [x] JSON output for CI — built into CLI
- [x] GitHub Action for PR checks — `.github/workflows/ci.yml` (typecheck → test → build on every PR + push to main)
- [x] npm publish workflow — `.github/workflows/publish.yml` (tag-based manual publish with gates)
- [~] Badge embed documentation — PARKED: only useful after registry is live with real scores

**Status:** Code-complete. CLI, CI, and publish workflows all implemented.

**Success Criteria:** 500 npm downloads in first month.

---

### Layer 5: Advanced Detection — COMPLETE (verified 2026-03-24)

**Goal:** Dynamic tool invocation testing, cross-server analysis.

**Deliverables:**
- [x] Gated dynamic testing — `packages/dynamic-tester/src/` (index.ts, consent.ts, canary.ts, audit-log.ts, output-scanner.ts, 5 test files)
  - 3 consent mechanisms: allowlist, tool_declaration, .well-known/mcp-sentinel.json
  - Read-only canary inputs, full audit trail
- [x] Cross-server risk matrix — `packages/risk-matrix/src/` (index.ts, patterns.ts, graph.ts, cli.ts, 2 test files)
  - 12 patterns P01–P12, capability graph, score caps
- [x] Red team validation — `packages/red-team/src/` (runner.ts, reporter.ts, cli.ts, 1 test file)
  - 900+ fixtures across 17 categories (A-Q), text/JSON/HTML reporting
  - L-Q categories verified: L(75), M(55), N(83), O(58), P(59), Q(81) fixtures
- [x] Rule accuracy auditing — AccuracyRunner with precision/recall metrics
- [x] Pipeline integration — Stage 5b in scanner, --dynamic flag in CLI, scan.yml risk-matrix job, accuracy.yml workflow
- [x] CLAUDE.md documentation for all three Layer 5 packages
- [x] Competitive benchmark framework — `packages/benchmark/src/` (index.ts, corpus.ts, competitors.ts, ground-truth.ts, report.ts)
  - 12-round reviewed, corpus of test fixtures, competitor comparison scoring
- [x] Python AST taint analysis — `packages/analyzer/src/rules/analyzers/` (taint.ts, taint-python.ts, taint-ast.ts)
  - tree-sitter-based Python AST parsing, source→sink taint propagation, cross-module import resolution
- [x] 5 highest-priority G-Q rules upgraded from regex-only to engine-native analysis
- [x] Ecosystem intelligence reports — `packages/reports/src/` (generator.ts, category-breakdown.ts, ecosystem-stats.ts, trend-analysis.ts, cli.ts)
  - Category breakdown, ecosystem stats, trend analysis, CLI for report generation

**Verification (2026-03-28):** All 1051 tests pass across 21 test files (1002 analyzer + 49 red-team). All 164/164 active TypedRules registered (13 retired). Pipeline audit clean. CI green.

**Success Criteria:** Detection precision >80% across all rule categories.

---

### Layer 6: Compliance & Enterprise

**Goal:** Compliance mapping, enterprise features, "State of MCP Security" report.

**Deliverables:**
- [ ] OWASP MCP Top 10 mapping complete
- [ ] MITRE ATLAS mapping complete
- [ ] EU AI Act readiness assessment template
- [ ] "State of MCP Security" quarterly report
- [ ] Responsible disclosure policy

**Success Criteria:** Report published, cited by 3+ publications.

---

### This Week's Priorities
1. Layer 3: SEO optimization (meta tags, Open Graph, structured data)
2. Layer 3: Content polish and final UI review

### What NOT To Build Now
- User authentication
- Payment/billing
- LLM-powered analysis
- Performance optimization
- Mobile UI

---

### Completed Work Summary (as of 2026-03-24)

| Component | Package | Key Files | Tests |
|-----------|---------|-----------|-------|
| Database | `packages/database` | schemas.ts, queries.ts, migrate.ts, seed.ts | — |
| 7 Crawlers | `packages/crawler` | sources/{npm,github,pypi,pulsemcp,smithery,mcpregistry,modelcontextprotocol-repo}.ts | 3 test files |
| Crawler orchestration | `packages/crawler` | orchestrator.ts, cli.ts | orchestrator.test.ts |
| MCP Connector | `packages/connector` | connector.ts | — |
| Analysis Engine | `packages/analyzer` | engine.ts (73 KB), rule-loader.ts, tool-fingerprint.ts | 2 test files |
| Python Taint Analysis | `packages/analyzer` | taint.ts, taint-python.ts, taint-ast.ts (2,442 lines) | — |
| 164 Active Detection Rules | `rules/` | 177 YAML files across A-Q categories (13 retired) | — |
| Scoring Algorithm | `packages/scorer` | scorer.ts, cli.ts | scorer.test.ts |
| Scan Pipeline | `packages/scanner` | pipeline.ts (30 KB), fetcher.ts, auditor.ts, enumerate.ts, cli.ts | scanner.test.ts |
| REST API | `packages/api` | server.ts (20 KB), badge.ts | 2 test files |
| Next.js Website | `packages/web` | 9 page routes (home, servers, detail, categories, dashboard, about, taxonomy) | — |
| CLI Tool | `packages/cli` | cli.ts (63 KB) | cli.test.ts |
| Dynamic Tester | `packages/dynamic-tester` | index.ts, consent.ts, canary.ts, audit-log.ts, output-scanner.ts | 5 test files |
| Risk Matrix | `packages/risk-matrix` | index.ts, patterns.ts, graph.ts, cli.ts | 2 test files |
| Red Team | `packages/red-team` | runner.ts, reporter.ts, cli.ts, 900+ fixtures | fixtures.test.ts |
| Benchmark | `packages/benchmark` | index.ts, corpus.ts, competitors.ts, ground-truth.ts, report.ts | — |
| Reports | `packages/reports` | generator.ts, category-breakdown.ts, ecosystem-stats.ts, trend-analysis.ts, cli.ts | — |
| CI/CD | `.github/workflows/` | ci.yml, crawl.yml, scan.yml, accuracy.yml, publish.yml | — |
| **Total** | **16 packages** | **~300 KB of core logic** | **21 test files, 1051 tests** |

---

### Parked Items (Deliberately Deferred — Resume When Conditions Change)

These are real deliverables, not abandoned. Each has a clear trigger for when to pick up.

| Item | Why Parked | Resume When |
|------|-----------|-------------|
| Crawler: Glama | No data volume need yet | Expanding crawler sources post-10k crawl |
| Crawler: awesome-mcp-servers | No data volume need yet | Expanding crawler sources post-10k crawl |
| Crawler: MCP Server Cards (.well-known/mcp) | New spec, low adoption so far | Standard gains traction in ecosystem |
| Deduplication pipeline | Only matters at crawl scale | 10k+ servers in DB, seeing real duplicates |
| Crawl orchestration logging (yield stats) | Nothing to observe at current scale | Running multi-source crawls regularly |
| Server author dispute mechanism | No servers scored yet, no disputes possible | Registry live with real scores + server authors contacting us |
| Badge embed documentation | Only useful after registry has real data | Registry live with scored servers |
