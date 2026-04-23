# MCP Sentinel — Product Milestones
## P12 Product Strategist Output — v1.1

_Last updated: 2026-04-23_

### Active Layer: Layer 6 (Compliance & Enterprise) — Phase 3 hallucination firewall + report publication

### 6-Layer Registry Plan

| Layer | Name | Status | Dependencies |
|-------|------|--------|-------------|
| 1 | Data Foundation | **COMPLETE** | None |
| 2 | Security Intelligence | **COMPLETE** | Layer 1 |
| 3 | Public Interface | **COMPLETE** — SEO polish landed | Layer 2 |
| 4 | Developer Tools | **COMPLETE** | Layer 3 |
| 5 | Advanced Detection | **COMPLETE** | Layer 4 |
| 6 | Compliance & Enterprise | **ACTIVE** — signed compliance reports (PR #205) and CVE replay corpus (PR #204) shipped; hallucination-firewall tests + public reports remaining | Layer 5 |

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
- [x] ~3350 tests passing across 190 test files — analyzer (~2853) + compliance-reports (142) + api (108) + red-team (~100 incl. 33 CVE-corpus harness + 22 CVE cases) + attack-graph (150). All 164 active rules registered; 13 retired disabled in YAML
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

**Verification (2026-04-23, post-Phase-5):** ~3350 tests pass across 190 test files in core packages — analyzer ~2853 across 162 files, compliance-reports 142 across 16 files, api 108 across 3 files, red-team ~100 across 4 files (incl. CVE corpus harness), attack-graph 150 across 5 files. All 164 active TypedRuleV2s registered; 13 retired disabled in YAML. 262 evidence chain assertions across 11 category test files. 163 benign corpus fixtures (zero critical/high findings tolerated). Evidence-integrity harness (Phase 2) enforces Location resolution + AST reachability + confidence derivation + CVE-manifest completeness on every rule. Mutation suite (Phase 2) aggregate survival rate 95.4% with always-fail parity guard. Per-rule accuracy dashboard (Phase 2) with CI regression gate. CVE replay corpus (Phase 4) — 22 cases pass end-to-end. Signed compliance reports (Phase 5) render HTML/PDF/JSON + SVG badges for all 7 frameworks. Pipeline audit clean. CI green.

**Success Criteria:** Detection precision >80% across all rule categories.

---

### Layer 6: Compliance & Enterprise — ACTIVE

**Goal:** Regulator-facing signed compliance artifacts + "State of MCP Security" public reports.

**Deliverables:**
- [x] **Adversarial Compliance Framework** — `packages/compliance-agents/` (ADR-009 LLM exception)
  - 6 framework agents: OWASP MCP, OWASP ASI, CoSAI, MAESTRO, EU AI Act, MITRE ATLAS
  - Hierarchy: FrameworkAgent → Category → ComplianceRule → ComplianceTest → ComplianceFinding
  - Dual-persona authoring protocol (CHARTER.md + sibling index.ts) with traceability guard
  - 4-step pipeline: deterministic gather → LLM synthesis → LLM execution → deterministic judge (hallucination firewall)
  - Shared rules across frameworks via `appliesTo[]`; orchestrator demultiplexes findings into per-framework reports
  - Isolation + combined modes: `pnpm compliance-scan --framework=eu_ai_act|all`
  - 3 new tables: `compliance_findings`, `compliance_agent_runs`, `compliance_test_cache` (append-only)
  - LLM audit log: every prompt/response/model/temperature persisted for replay
  - Confidence cap at 0.85 for LLM-derived findings; mock LLM client default for reproducibility
  - No-static-patterns guard + charter-traceability guard enforce "no regex, nothing static" in `src/rules/`
- [x] **CVE Replay Corpus** — `packages/red-team/src/cve-corpus/` (Phase 4, PR #204)
  - Harness contract at `docs/standards/cve-replay-corpus-spec.md`
  - 22 falsifiable cases: 16 CVEs (CVE-2025-6514, 6515, 53109, 53110, 53773, 54135, 59536, 59944, 68143, 68144, 68145, 2017-5941, 30066, 2026-21852, 22785, 29787) + 6 research replays (Embrace-The-Red, Invariant Labs, Trail of Bits, CyberArk FSP+ATPA, MPMA)
  - Auto-generated `docs/cve-coverage.md` — 20 unique rules covered, 143 uncovered rules listed transparently
  - 33 harness self-tests + 22/22 real cases pass end-to-end
- [x] **Regulator-Facing Signed Compliance Reports** — `packages/compliance-reports/` (Phase 5, PR #205)
  - Data model: `ComplianceReport`, `SignedComplianceReport`, `ControlResult`, `KillChainNarrative`
  - RFC 8785 JSON canonicalization (byte-for-byte reproducible; regulators verify offline)
  - HMAC-SHA256 attestation via Node's built-in `crypto` (no crypto deps)
  - 7 framework registries: EU AI Act, ISO 27001, OWASP MCP, OWASP ASI, CoSAI, MAESTRO, MITRE ATLAS — 62 controls total, 61 with assessor rules, 1 honest gap (ASI10 Agentic Data Poisoning — out of scope for an MCP scanner)
  - HTML/PDF/JSON renderers (21 (format × framework) registrations from single shared impl per format)
  - PDF via `pdfkit` with deterministic CreationDate/ModDate pinned to `signed_at`
  - Kill-chain narrative synthesizer wires KC01–KC07 to Phase 4 CVE corpus evidence (KC07 honest gap: no Phase 4 exemplar yet)
  - 7 per-framework SVG badges (shields.io-style with framework accent colors + attestation in XML comment)
  - Signed API endpoints at `packages/api`: `GET /api/v1/servers/:slug/compliance/:framework.{json,html,pdf}` + `/badge.svg`
  - Response headers: `X-MCP-Sentinel-{Signature,Key-Id,Signed-At,Algorithm,Canonicalization}`
  - 142/142 compliance-reports tests + 108/108 api tests
- [x] OWASP MCP Top 10 mapping complete (10/10 covered in `frameworks/owasp_mcp.ts`)
- [x] OWASP Agentic Top 10 mapping complete (9/10 — ASI10 honest gap)
- [x] MITRE ATLAS mapping complete (9/9 covered in `frameworks/mitre_atlas.ts`)
- [x] EU AI Act readiness assessment template (5 articles covered: Art. 9, 12, 13, 14, 15)
- [ ] Production signing keys wired — `COMPLIANCE_SIGNING_KEY` + `COMPLIANCE_SIGNING_KEY_ID` in Railway env (launch-blocker)
- [ ] **Phase 3 — hallucination firewall** (parked; resume to ship regulator-grade LLM verdict testing)
  - 3.1 Judge triad (26 × 3 = 78 tests per rule)
  - 3.2 LLM-replay adversarial corpus (20 recorded bad responses)
  - 3.3 Confidence-cap enforcement test (every LLM finding ≤ 0.85 with `analysis_technique: "llm-reasoning"`)
- [ ] "State of MCP Security" quarterly report (via `packages/reports/`)
- [ ] Competitive benchmark publication (via `packages/benchmark/`)
- [ ] Responsible disclosure policy

**Success Criteria:** Compliance report endpoints live + signed; "State of MCP Security" published, cited by 3+ publications.

---

### This Week's Priorities
1. Layer 6: resume Phase 3 (compliance-agents hallucination firewall — judge triad, LLM-replay corpus, confidence-cap enforcement)
2. Layer 6: wire production signing keys (`COMPLIANCE_SIGNING_KEY`/`COMPLIANCE_SIGNING_KEY_ID`) before public launch
3. Layer 6: publish "State of MCP Security Q2 2026" via `packages/reports/`

### What NOT To Build Now
- User authentication
- Payment/billing
- LLM-powered analysis _outside_ `packages/compliance-agents/` (ADR-009 keeps the exception scoped)
- Performance optimization
- Mobile UI

---

### Completed Work Summary (as of 2026-04-23)

| Component | Package | Key Files | Tests |
|-----------|---------|-----------|-------|
| Database | `packages/database` | schemas.ts, queries.ts, migrate.ts, seed.ts | — |
| 7 Crawlers | `packages/crawler` | sources/{npm,github,pypi,pulsemcp,smithery,mcpregistry,modelcontextprotocol-repo}.ts | 3 test files |
| Crawler orchestration | `packages/crawler` | orchestrator.ts, cli.ts | orchestrator.test.ts |
| MCP Connector | `packages/connector` | connector.ts | — |
| Analysis Engine | `packages/analyzer` | engine.ts (post-1.28 cutover: 463 lines, was 2177), rule-loader.ts, tool-fingerprint.ts | 162 test files, ~2853 tests |
| 164 Active TypedRuleV2 Implementations | `packages/analyzer/src/rules/implementations/<rule-id>/` | 164 per-rule dirs (CHARTER + gather + verification + index + data/ + __fixtures__/ + __tests__/) | 262 evidence chain assertions |
| Python Taint Analysis | `packages/analyzer` | taint.ts, taint-python.ts, taint-ast.ts | — |
| Test Infrastructure (Phase 2) | `packages/analyzer/__tests__/` | evidence-integrity, mutation-charter-parity, benign-catalogue, no-static-patterns, charter-traceability | 163 benign corpus fixtures; mutation suite 95.4% survival |
| Scoring Algorithm | `packages/scorer` | scorer.ts, cli.ts | scorer.test.ts |
| Scan Pipeline | `packages/scanner` | pipeline.ts (calls `analyzeWithProfile()` for evidence chain persistence), fetcher.ts, auditor.ts, enumerate.ts, cli.ts | scanner.test.ts |
| REST API | `packages/api` | server.ts + compliance-report-routes.ts (signed endpoints) + badge.ts | 3 test files, 108 tests |
| Compliance Reports (Phase 5) | `packages/compliance-reports` | types.ts, canonicalize.ts (RFC 8785), attestation.ts (HMAC-SHA256), frameworks/ (7), build-report.ts, render/ (HTML/PDF/JSON × 21 regs), kill-chain/, badges/ | 16 test files, 142 tests |
| Next.js Website | `packages/web` | 9 page routes (home, servers, detail, categories, dashboard, about, taxonomy) | — |
| CLI Tool | `packages/cli` | cli.ts | cli.test.ts |
| MCP Scanner Server | `packages/mcp-sentinel-scanner` | index.ts (MCP server exposing scanning as tools) | smoke tests |
| Dynamic Tester | `packages/dynamic-tester` | index.ts, consent.ts, canary.ts, audit-log.ts, output-scanner.ts | 5 test files |
| Risk Matrix | `packages/risk-matrix` | index.ts, patterns.ts, graph.ts, cli.ts | 2 test files |
| Attack Graph | `packages/attack-graph` | engine, scoring, narratives, KC01-KC07 templates | 5 test files, 150 tests |
| Red Team (incl. Phase 4 CVE corpus) | `packages/red-team` | runner.ts, reporter.ts, accuracy/, mutation/, cve-corpus/ (22 cases), 900+ fixtures | 4 test files, ~100 tests |
| Benchmark | `packages/benchmark` | index.ts, corpus.ts, competitors.ts, ground-truth.ts, report.ts | — |
| Reports | `packages/reports` | generator.ts, category-breakdown.ts, ecosystem-stats.ts, trend-analysis.ts, cli.ts | — |
| Compliance Agents | `packages/compliance-agents` | 6 framework agents, LLM-gated per ADR-009, mock-LLM default + judge() firewall | integration/smoke tests |
| CI/CD | `.github/workflows/` | ci.yml, crawl.yml, scan.yml, accuracy.yml, publish.yml | — |
| **Total** | **17 packages** | **~400+ KB of core logic** | **190 test files, ~3350 tests (in core packages)** |

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
