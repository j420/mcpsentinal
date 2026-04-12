# MCP Sentinel — Architecture Document
## P4 Registry Architect Output — v1.0

### Architecture Decision Records

**ADR-001: TypeScript Monorepo with pnpm workspaces**
- Decision: Use TypeScript throughout, pnpm workspaces for package management, turborepo for orchestration.
- Rationale: MCP SDK is TypeScript-native. Single language reduces complexity. pnpm workspaces provide good monorepo support.

**ADR-002: PostgreSQL as sole data store**
- Decision: PostgreSQL with full-text search (tsvector), no separate search engine.
- Rationale: At <50K servers, PostgreSQL FTS is sufficient. Avoids operational complexity of Elasticsearch. Can migrate later if needed.

**ADR-003: Pipeline architecture with clear stage boundaries**
- Decision: 6-stage pipeline: Discovery → Connection → Analysis → Scoring → Enrichment → Publication.
- Rationale: Each stage has independent retry/failure modes. Allows partial re-processing.

**ADR-004: Zod schemas as contracts between packages**
- Decision: Shared Zod schemas define the data contract between pipeline stages.
- Rationale: Runtime validation + TypeScript types from single source. Catches data quality issues at stage boundaries.

**ADR-005: YAML metadata + TypeScript TypedRules**
- Decision: YAML files in rules/ define metadata only (id, severity, owasp, mitre, remediation, test_cases). All detection logic lives in TypeScript TypedRule implementations in `packages/analyzer/src/rules/implementations/`.
- Rationale: TypeScript enables AST taint analysis, capability graph algorithms, entropy scoring, and structural parsing — techniques impossible in YAML regex. All rules migrated to TypedRules. 164 active (13 retired due to high FP rates).
- History: Originally YAML regex (v0.1). Migrated to TypedRules (v0.2). Zero YAML regex patterns remain.

**ADR-006: No LLM in v1 — all analysis is deterministic**
- Decision: No LLM API calls in v1. All detection is AST taint analysis, capability graph algorithms, Shannon entropy, structural parsing, and linguistic pattern scoring.
- Rationale: Correctness over coverage. Deterministic rules produce reproducible results. LLM classification added in v1.1 only where a deterministic rule demonstrably fails.
- Trigger: A rule category shows >5% false-positive rate in Layer 5 red team audit.

**ADR-007: Never invoke MCP server tools — legal/ethical boundary**
- Decision: MCPConnector ONLY calls `initialize` and `tools/list`. `tools/call` is a Layer 5 gated capability requiring explicit server-author opt-in.
- Rationale: Invoking tools has side effects. A scanner that executes code, reads files, or sends network requests on scanned servers without consent is legally and ethically indefensible. This is not a performance preference.
- Enforcement: `.claude/hooks/pre-tool-use/block-mcp-invocation.sh` blocks attempts automatically.
- Dynamic invocation: Layer 5 only, full audit log, read-only canary inputs only, explicit opt-in required.

**ADR-008: Immutable scan results — history is a first-class feature**
- Decision: `findings` and `scores` tables are append-only. No UPDATE statements. Every change generates a new record.
- Rationale: Score trends and G6 (rug-pull detection) require reliable historical baselines. Mutable records make trend data meaningless.
- Consequence: Never add UPDATE to findings or scores. If a finding is disputed, set `disputed: true` — never delete.

**ADR-009: LLM exception scoped to `packages/compliance-agents/`**
- Decision: ADR-006 ("no LLM in v1") is lifted **only** for the new `packages/compliance-agents/` package. Every other package — analyzer, scorer, scanner, crawler, attack-graph, dynamic-tester, red-team — remains 100% deterministic. The compliance agents may call Anthropic Claude to (a) synthesize per-server adversarial test cases, (b) reason about whether evidence violates a control, and (c) produce natural-language compliance narratives.
- Rationale: The user's product requirement for the compliance framework is *dynamic, non-deterministic, edge-case-only* tests synthesized per server. A purely deterministic implementation cannot satisfy "dynamic test generation per server" — that is exactly what the LLM is for. Keeping the exception scoped means the existing 164-rule deterministic pipeline and its reproducibility guarantees are unaffected.
- Hallucination firewall: every LLM verdict is re-validated by a deterministic `judge()` method on the rule. The LLM only sees a typed `EvidenceBundle` produced by a deterministic gather step — never raw server source code on its own. Verdicts the judge cannot confirm are discarded.
- Reproducibility: every prompt + response + model + temperature + token counts is persisted to `compliance_agent_runs` (append-only per ADR-008). Auditors can replay any compliance scan by re-running the cached prompts.
- Confidence cap: LLM-derived findings are capped at confidence 0.85 (vs 0.99 for deterministic rules) and tagged `analysis_technique: 'llm-reasoning'`.
- Default mode: compliance scans default to `MockLLMClient` (recorded responses keyed by cache_key). The live Anthropic SDK client is only invoked with `--live` and a valid `ANTHROPIC_API_KEY`.
- Enforcement: only files under `packages/compliance-agents/src/llm/` may import the Anthropic SDK. Two CI guards (`__tests__/no-static-patterns.test.ts` and `__tests__/charter-traceability.test.ts`) enforce the dual-persona authoring protocol — no regex literals or long string-array constants in `src/rules/`, and every rule's CHARTER.md must agree with its TypeScript implementation on rule id, threat refs, and edge-case strategies.

---

### Data Model

```
┌─────────────┐      ┌───────────────┐      ┌──────────────┐
│   servers    │──1:N─│    tools      │──1:N─│  parameters  │
│             │      │               │      │              │
│ id (PK)     │      │ id (PK)       │      │ id (PK)      │
│ name        │      │ server_id(FK) │      │ tool_id (FK) │
│ slug        │      │ name          │      │ name         │
│ description │      │ description   │      │ type         │
│ author      │      │ input_schema  │      │ required     │
│ github_url  │      │ capability_tags│     │ constraints  │
│ npm_package │      │ created_at    │      │ description  │
│ pypi_package│      │ updated_at    │      └──────────────┘
│ category    │      └───────────────┘
│ language    │
│ license     │      ┌───────────────┐      ┌──────────────┐
│ github_stars│──1:N─│   findings    │      │    rules     │
│ npm_downloads│     │               │      │              │
│ last_commit │      │ id (PK)       │      │ id (PK)      │
│ latest_score│      │ server_id(FK) │      │ rule_id      │
│ created_at  │      │ scan_id (FK)  │      │ name         │
│ updated_at  │      │ rule_id       │      │ category     │
│ search_vector│     │ severity      │      │ severity     │
└─────────────┘      │ evidence      │      │ owasp        │
      │              │ remediation   │      │ mitre        │
      │              │ owasp_category│      │ detect_config│
      │ 1:N          │ mitre_technique│     │ remediation  │
      │              │ disputed      │      │ enabled      │
      ▼              │ created_at    │      └──────────────┘
┌─────────────┐      └───────────────┘
│   scans     │
│             │      ┌───────────────┐
│ id (PK)     │      │   scores      │
│ server_id   │──1:1─│               │
│ status      │      │ id (PK)       │
│ started_at  │      │ server_id(FK) │
│ completed_at│      │ scan_id (FK)  │
│ rules_version│     │ total_score   │
│ error       │      │ code_score    │
│ findings_cnt│      │ deps_score    │
└─────────────┘      │ config_score  │
      │              │ description_score│
      │              │ behavior_score│
┌─────────────┐      │ owasp_coverage│
│  sources    │      │ created_at    │
│             │      └───────────────┘
│ id (PK)     │
│ server_id   │      ┌───────────────┐
│ source_name │      │score_history  │
│ source_url  │      │               │
│ external_id │      │ id (PK)       │
│ raw_metadata│      │ server_id(FK) │
│ last_synced │      │ score         │
│ created_at  │      │ findings_count│
└─────────────┘      │ recorded_at   │
                     └───────────────┘
┌─────────────┐      ┌───────────────┐
│dependencies │      │  incidents    │
│             │      │               │
│ id (PK)     │      │ id (PK)       │
│ server_id   │      │ server_id(FK) │
│ name        │      │ date          │
│ version     │      │ description   │
│ ecosystem   │      │ root_cause    │
│ has_known_cve│     │ owasp_category│
│ cve_ids     │      │ mitre_technique│
│ last_updated│      │ source_url    │
└─────────────┘      │ created_at    │
                     └───────────────┘
```

---

### Pipeline Specification

**Stage 1: Discovery (packages/crawler)**
- Input: Source configurations (registry URLs, API keys)
- Process: Crawl each source, extract server metadata, normalize
- Output: `DiscoveredServer[]` → database via ingestion pipeline
- Error handling: Per-source retry with exponential backoff, partial success OK
- Data quality: Must have at least one identifier (github_url OR npm_package OR pypi_package)

**Stage 2: Connection (packages/connector)**
- Input: Server records with connectable endpoints
- Process: MCP SDK `initialize` + `tools/list`, enumerate tools and parameters
- Output: `ToolEnumeration[]` → updates server.tools in database
- Error handling: 30s timeout per server, record connection failures
- Safety: NEVER invoke tools. Only `initialize` and `tools/list`.

**Stage 3: Analysis (packages/analyzer)**
- Input: Server record with tools, parameters, source code (if available)
- Process: Two-phase analysis:
  1. **Specialized engines** (DescriptionAnalyzer, CodeAnalyzer, SchemaAnalyzer, DependencyAnalyzer, ProtocolAnalyzer) run first for rules they own
  2. **TypedRule dispatch** for rules not covered by engines — 164 active TypedRules using AST taint, capability graph, entropy, structural parsing (13 retired)
- Companion rule pattern: Some parent rules emit findings for multiple rule IDs (e.g. F1→F2/F3/F6, I1→I2, L5→L14). Companion rules are registered as stubs returning `[]` to prevent engine warnings — the parent rule produces their findings during its own analysis.
- Output: `Finding[]` → findings table (with confidence scores 0.0-1.0)
- Error handling: Per-rule error isolation (one rule failing doesn't stop others)
- Data quality: Every finding must have rule_id, evidence, remediation, confidence
- Analysis infrastructure: `taint-ast.ts` (803 lines), `taint.ts` (676 lines), `capability-graph.ts` (761 lines), `module-graph.ts` (826 lines), `entropy.ts` (449 lines), `similarity.ts` (477 lines)

**Stage 4: Scoring (packages/scorer)**
- Input: Findings for a server
- Process: Apply weighted scoring algorithm
- Output: `Score` → scores table + update server.latest_score
- Algorithm: 100 - sum(weighted penalties). See scoring-algorithm.md.

**Stage 5: Enrichment (future — packages/connector extended)**
- Input: Server record
- Process: Fetch GitHub stats, npm download counts, dependency audit
- Output: Enriched server record

**Stage 6: Publication (packages/api + packages/web)**
- Input: Scored server records
- Process: Serve via REST API and Next.js website
- Output: Public registry

---

### API Contract

**Public API (packages/api)**

```
GET  /api/v1/servers                  → ServerListResponse (paginated, filterable)
     ?q=<search>&category=<cat>&min_score=<n>&max_score=<n>&sort=<field>&order=asc|desc&page=<n>&limit=<n>

GET  /api/v1/servers/:slug            → ServerDetailResponse
GET  /api/v1/servers/:slug/findings   → FindingListResponse
GET  /api/v1/servers/:slug/score      → ScoreDetailResponse
GET  /api/v1/servers/:slug/history    → ScoreHistoryResponse
GET  /api/v1/servers/:slug/badge.svg  → SVG badge image

GET  /api/v1/ecosystem/stats          → EcosystemStatsResponse
GET  /api/v1/ecosystem/categories     → CategoryListResponse

POST /api/v1/scan                     → ScanRequestResponse (authenticated)
     { "server_url": "..." }
```

---

### Technical Debt Register

| Item | Severity | When to Fix |
|------|----------|-------------|
| No queue system — scanning is synchronous | Medium | When scan time > 5min per batch |
| No caching layer for API | Low | When API traffic > 100 req/min |
| FTS on PostgreSQL instead of dedicated search | Low | When servers > 50K |
| No rate limiting on public API | Medium | Before public launch |
| No background job scheduler | Medium | Resolved: GitHub Actions is the scheduler |

---

## Production Architecture
### P7 Infrastructure Engineer Output — v1.0

### Design Principles

1. **No always-on workers.** GitHub Actions runners spin up, run the pipeline, and exit. Zero idle cost. At current scale (<10k servers), this is the right trade-off. Migrate to a persistent queue (BullMQ/Redis) only when scan batches exceed 1 hour.
2. **Railway for serving, GitHub Actions for processing.** Railway hosts the live API and website (persistent, low-latency). GitHub Actions runs the data pipeline (bursty, high-memory, tolerates cold starts).
3. **PostgreSQL as the single source of truth.** No Redis cache, no S3 artifacts, no separate search index. Railway PostgreSQL is accessed by both the pipeline (writes) and the API (reads). At 50k+ servers, add a read replica.
4. **Append-only scan results.** ADR-008: findings and scores are never updated, only inserted. This enables G6 (rug-pull detection) and trend analysis without any extra infrastructure.

---

### Production Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GITHUB ACTIONS (Data Pipeline)                      │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  crawl.yml  — Sundays 02:00 UTC + manual                             │  │
│  │                                                                      │  │
│  │   migrate ──→ [in parallel]                                          │  │
│  │                ├── crawl-smithery      (timeout: 30m)                │  │
│  │                ├── crawl-pulsemcp      (timeout: 30m)                │  │
│  │                ├── crawl-npm           (timeout: 30m)                │  │
│  │                ├── crawl-pypi          (timeout: 30m)                │  │
│  │                ├── crawl-github        (timeout: 30m)                │  │
│  │                └── crawl-official-reg  (timeout: 30m)                │  │
│  │                         └──→ crawl-summary                           │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│           │ workflow_run: completed                                          │
│           ▼                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  scan.yml  — Daily 04:00 UTC + after crawl + manual                  │  │
│  │                                                                      │  │
│  │   check-trigger ──→ migrate ──→ scan ──→ score ──→ summary           │  │
│  │                                 │                                    │  │
│  │                  modes:         ├── incremental  (default)           │  │
│  │                                 ├── rescan-failed                    │  │
│  │                                 └── full                             │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │  ci.yml  — Every PR + push to main                                   │  │
│  │   typecheck ──→ test ──→ build                                       │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬────────────────────────────────────────────┘
                                 │ reads/writes
                                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         RAILWAY (Always-On Services)                        │
│                                                                             │
│   ┌──────────────────┐    ┌──────────────────┐    ┌─────────────────────┐  │
│   │  PostgreSQL DB    │    │  API Service      │    │  Web Service        │  │
│   │  (managed)        │◄───│  (Express)        │    │  (Next.js)          │  │
│   │                   │    │  packages/api     │    │  packages/web       │  │
│   │  mcp_sentinel DB  │    │  auto-deploy:main │    │  auto-deploy:main   │  │
│   │  port: 5432       │    │  port: 3001       │    │  port: 3000         │  │
│   └──────────────────┘    └──────────────────┘    └─────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                                             │
                                                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PUBLIC INTERNET                                │
│                                                                             │
│   mcp-sentinel.com  (Next.js website — searchable registry)                │
│   api.mcp-sentinel.com  (REST API — badge embeds, developer integrations)  │
│   npmjs.com/package/mcp-sentinel  (CLI: npx mcp-sentinel check)            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Pipeline Execution Schedule

| Workflow | Schedule | Manual Dispatch | What It Does |
|----------|----------|-----------------|-------------|
| `crawl.yml` | Sundays 02:00 UTC | Yes — per-source | 6 crawlers in parallel → DB |
| `scan.yml` | Daily 04:00 UTC | Yes — mode + batch_size + server_id | scan + score pipeline |
| `ci.yml` | Every PR/push to main | No | typecheck + test + build |

**Auto-chain:** `crawl.yml` completion triggers `scan.yml` via `workflow_run`. The daily `scan.yml` schedule is a safety net that catches servers discovered outside the weekly crawl (e.g. via API or manual DB inserts).

**Concurrency guard:** `scan.yml` uses `concurrency: group: scan-pipeline, cancel-in-progress: false`. A second scan trigger queues rather than cancels the running scan. This prevents a daily cron from killing a weekly full rescan mid-flight.

---

### GitHub Actions Secrets

| Secret | Required By | Description |
|--------|-------------|-------------|
| `DATABASE_URL` | crawl.yml, scan.yml | Railway PostgreSQL connection string. Format: `postgresql://user:pass@host:port/db` |
| `SMITHERY_API_KEY` | crawl.yml (smithery job) | Smithery registry API key |
| `GITHUB_TOKEN` | scan.yml (scan job) | Auto-injected by Actions. Used for GitHub raw content fetch (source code analysis) and GitHub Search API. Rate limit: 5,000 req/hr. |

**Where to set:** GitHub repo → Settings → Secrets and variables → Actions → New repository secret.

**`GITHUB_TOKEN` note:** The auto-injected token is scoped to the repo. The scanner uses it for fetching source code from third-party repos (GitHub raw content API). The 5,000 req/hr limit is sufficient for incremental scans but may constrain full rescans at 10k+ servers. If rate-limiting becomes an issue, add a `GITHUB_PAT` secret with a personal access token.

---

### Scan Modes

| Mode | When to Use | Behavior |
|------|-------------|----------|
| `incremental` | Default, daily runs | Scans servers with `last_scan_at IS NULL`. Fast. |
| `rescan-failed` | After fixing a bug in the scanner | Scans servers where last scan `status = 'error'` |
| `full` | After adding new detection rules | Rescans all servers. Slow — use on weekends. |
| `--server=<id>` | Debugging a specific server | Scans one server by DB ID. Ignores mode. |

---

### Failure Modes and Recovery

| Failure | Impact | Recovery |
|---------|--------|----------|
| DB migration fails | crawl + scan blocked (hard dependency) | Fix migration SQL, re-run workflow |
| Crawl partial failure (1-2 sources) | Fewer new servers discovered | Remaining sources still wrote rows; run single-source via `workflow_dispatch` |
| Scan timeout (>5h) | Some servers not scanned | Re-run with `mode=incremental` — already-scanned servers are skipped |
| Score job fails | Findings in DB but `latest_score` stale | Run `pnpm score` locally or re-trigger scan.yml |
| Railway API down | Public registry unavailable | Railway provides auto-restart; check Railway dashboard |
| GitHub rate limit hit | Source code fetch fails for some servers | Scanner records error per server; re-run next day |

---

### Railway Service Configuration

```
# packages/api — Railway service
Builder:        Dockerfile
Dockerfile:     packages/api/Dockerfile
Build Context:  . (repo root)
Config file:    railway.toml (repo root)
Health check:   GET /health → 200 OK
Auto-deploy:    main branch push
Env vars:       DATABASE_URL  ← use PUBLIC TCP proxy URL from PostgreSQL → Connect tab
                              ← format: postgresql://postgres:pass@host.proxy.rlwy.net:PORT/railway
                              ← DO NOT use postgres.railway.internal — only works if Railway
                              ← private networking is explicitly enabled for both services
                PORT=3100

# packages/web — Railway service
Builder:        Dockerfile
Dockerfile:     packages/web/Dockerfile   ← set explicitly in service Settings → Build
Build Context:  . (repo root)             ← Railway does NOT auto-use packages/web/railway.toml
Config file:    packages/web/railway.toml ← set via Settings → Source → Config File Path
Health check:   GET / → 200 OK
Auto-deploy:    main branch push
Env vars:       NEXT_PUBLIC_API_URL=https://api.mcp-sentinel.com
                PORT=3000                 ← REQUIRED: Railway defaults PORT=8080 which mismatches
                                          ← EXPOSE 3000 in the Dockerfile, causing 502 errors
```

### Railway Gotchas (Learned the Hard Way)

| Gotcha | Symptom | Fix |
|--------|---------|-----|
| Root `railway.toml` applies to all services by default | Web service runs API code | Set Dockerfile path explicitly in web service Settings → Build |
| `postgres.railway.internal` not resolvable | `getaddrinfo ENOTFOUND` on API startup | Use public TCP proxy URL from PostgreSQL → Connect tab |
| Railway injects `PORT=8080` by default | Next.js listens on 8080, Railway routes to 3000 → 502 | Add `PORT=3000` env var to web service |

---

### Adding a New Pipeline Stage

1. Build it as a new package under `packages/`
2. Add a build step in `scan.yml` after the `install` step
3. Add a new job in `scan.yml` with `needs: [previous-stage]`
4. Add the new job to the `summary` job's `needs` array
5. Update this doc

**Do NOT** add the new stage to `ci.yml` unless it needs to run on every PR. Pipeline stages are data-processing jobs, not build artifacts.
