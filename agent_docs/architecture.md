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

**ADR-005: YAML detection rules interpreted by engine**
- Decision: Detection rules stored as YAML in rules/ directory. Analyzer interprets them.
- Rationale: Adding a rule should never require engine code changes. Rules are data.

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
- Process: Run all applicable detection rules, produce findings
- Output: `Finding[]` → findings table
- Error handling: Per-rule error isolation (one rule failing doesn't stop others)
- Data quality: Every finding must have rule_id, evidence, remediation

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
| No background job scheduler | Medium | When crawlers need to run on schedule |
