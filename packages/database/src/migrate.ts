import pg from "pg";
import pino from "pino";

const logger = pino({ name: "db:migrate" });

const MIGRATIONS = [
  {
    id: "001_initial_schema",
    sql: `
      -- Enable UUID generation
      CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
      CREATE EXTENSION IF NOT EXISTS "pg_trgm";

      -- Servers: canonical record per unique MCP server
      CREATE TABLE IF NOT EXISTS servers (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        name VARCHAR(500) NOT NULL,
        slug VARCHAR(500) NOT NULL UNIQUE,
        description TEXT,
        author VARCHAR(500),
        github_url TEXT,
        npm_package VARCHAR(500),
        pypi_package VARCHAR(500),
        category VARCHAR(50),
        language VARCHAR(50),
        license TEXT,
        github_stars INTEGER,
        npm_downloads INTEGER,
        last_commit TIMESTAMPTZ,
        latest_score INTEGER CHECK (latest_score >= 0 AND latest_score <= 100),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        search_vector tsvector GENERATED ALWAYS AS (
          setweight(to_tsvector('english', coalesce(name, '')), 'A') ||
          setweight(to_tsvector('english', coalesce(description, '')), 'B') ||
          setweight(to_tsvector('english', coalesce(author, '')), 'C')
        ) STORED
      );

      CREATE INDEX IF NOT EXISTS idx_servers_slug ON servers(slug);
      CREATE INDEX IF NOT EXISTS idx_servers_category ON servers(category);
      CREATE INDEX IF NOT EXISTS idx_servers_latest_score ON servers(latest_score);
      CREATE INDEX IF NOT EXISTS idx_servers_github_url ON servers(github_url) WHERE github_url IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_servers_npm_package ON servers(npm_package) WHERE npm_package IS NOT NULL;
      CREATE INDEX IF NOT EXISTS idx_servers_search ON servers USING gin(search_vector);
      CREATE INDEX IF NOT EXISTS idx_servers_name_trgm ON servers USING gin(name gin_trgm_ops);

      -- Tools: one row per tool per server
      CREATE TABLE IF NOT EXISTS tools (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        name VARCHAR(500) NOT NULL,
        description TEXT,
        input_schema JSONB,
        capability_tags TEXT[] DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(server_id, name)
      );

      CREATE INDEX IF NOT EXISTS idx_tools_server_id ON tools(server_id);

      -- Parameters: one row per parameter per tool
      CREATE TABLE IF NOT EXISTS parameters (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
        name VARCHAR(500) NOT NULL,
        type VARCHAR(100) NOT NULL DEFAULT 'string',
        required BOOLEAN NOT NULL DEFAULT false,
        description TEXT,
        constraints JSONB,
        UNIQUE(tool_id, name)
      );

      CREATE INDEX IF NOT EXISTS idx_parameters_tool_id ON parameters(tool_id);

      -- Scans: scan metadata
      CREATE TABLE IF NOT EXISTS scans (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ,
        rules_version VARCHAR(50) NOT NULL DEFAULT '1.0.0',
        error TEXT,
        findings_count INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_scans_server_id ON scans(server_id);
      CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

      -- Findings: security findings per server per scan
      CREATE TABLE IF NOT EXISTS findings (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        rule_id VARCHAR(50) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        evidence TEXT NOT NULL,
        remediation TEXT NOT NULL,
        owasp_category VARCHAR(50),
        mitre_technique VARCHAR(100),
        disputed BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_findings_server_id ON findings(server_id);
      CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
      CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

      -- Scores: composite scores per server per scan
      CREATE TABLE IF NOT EXISTS scores (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        total_score INTEGER NOT NULL CHECK (total_score >= 0 AND total_score <= 100),
        code_score INTEGER NOT NULL DEFAULT 100,
        deps_score INTEGER NOT NULL DEFAULT 100,
        config_score INTEGER NOT NULL DEFAULT 100,
        description_score INTEGER NOT NULL DEFAULT 100,
        behavior_score INTEGER NOT NULL DEFAULT 100,
        owasp_coverage JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(server_id, scan_id)
      );

      CREATE INDEX IF NOT EXISTS idx_scores_server_id ON scores(server_id);

      -- Sources: which registries list this server
      CREATE TABLE IF NOT EXISTS sources (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        source_name VARCHAR(50) NOT NULL,
        source_url TEXT,
        external_id VARCHAR(500),
        raw_metadata JSONB NOT NULL DEFAULT '{}',
        last_synced TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(server_id, source_name, external_id)
      );

      CREATE INDEX IF NOT EXISTS idx_sources_server_id ON sources(server_id);
      CREATE INDEX IF NOT EXISTS idx_sources_source_name ON sources(source_name);

      -- Dependencies: npm/pip dependencies per server
      CREATE TABLE IF NOT EXISTS dependencies (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        name VARCHAR(500) NOT NULL,
        version VARCHAR(100),
        ecosystem VARCHAR(20) NOT NULL,
        has_known_cve BOOLEAN NOT NULL DEFAULT false,
        cve_ids TEXT[] DEFAULT '{}',
        last_updated TIMESTAMPTZ,
        UNIQUE(server_id, name, ecosystem)
      );

      CREATE INDEX IF NOT EXISTS idx_dependencies_server_id ON dependencies(server_id);
      CREATE INDEX IF NOT EXISTS idx_dependencies_has_cve ON dependencies(has_known_cve) WHERE has_known_cve = true;

      -- Incidents: real-world security incidents
      CREATE TABLE IF NOT EXISTS incidents (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID REFERENCES servers(id) ON DELETE SET NULL,
        date TIMESTAMPTZ NOT NULL,
        description TEXT NOT NULL,
        root_cause TEXT,
        owasp_category VARCHAR(50),
        mitre_technique VARCHAR(100),
        source_url TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      -- Score history: immutable record of score changes
      CREATE TABLE IF NOT EXISTS score_history (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
        findings_count INTEGER NOT NULL DEFAULT 0,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_score_history_server_id ON score_history(server_id);
      CREATE INDEX IF NOT EXISTS idx_score_history_recorded_at ON score_history(recorded_at);

      -- Migrations tracking table
      CREATE TABLE IF NOT EXISTS _migrations (
        id VARCHAR(100) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `,
  },
  {
    id: "002_widen_license_column",
    sql: `ALTER TABLE servers ALTER COLUMN license TYPE TEXT;`,
  },
  {
    id: "003_crawl_runs",
    sql: `
      -- Crawl run history: persists aggregate stats for every crawl execution.
      -- Enables yield trend analysis per source over time (was it worth crawling?).
      -- Append-only — never UPDATE (ADR-008: history by default).
      CREATE TABLE IF NOT EXISTS crawl_runs (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        total_discovered INTEGER NOT NULL DEFAULT 0,
        new_to_db INTEGER NOT NULL DEFAULT 0,
        enriched_existing INTEGER NOT NULL DEFAULT 0,
        persist_errors INTEGER NOT NULL DEFAULT 0,
        per_source JSONB NOT NULL DEFAULT '[]',
        data_quality JSONB NOT NULL DEFAULT '{}',
        elapsed_ms INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_crawl_runs_started_at ON crawl_runs(started_at);
    `,
  },
  {
    id: "004_enhanced_product_columns",
    sql: `
      -- servers: denormalized connection + scan columns
      -- last_scanned_at: replaces slow NOT EXISTS subquery in getUnscannedServers
      -- endpoint_url:    cache discovered HTTP endpoint — avoid re-scanning raw_metadata
      -- tool_count:      denormalized for UI sort/filter without JOIN
      -- connection_status: surface health status in web UI (success/failed/timeout/no_endpoint)
      -- server_version:  MCP initialize serverInfo.version — H2 rule data, persisted for history
      -- server_instructions: MCP initialize instructions field — H2 rule data, persisted for history
      ALTER TABLE servers
        ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS endpoint_url TEXT,
        ADD COLUMN IF NOT EXISTS tool_count INTEGER NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS connection_status VARCHAR(20),
        ADD COLUMN IF NOT EXISTS server_version TEXT,
        ADD COLUMN IF NOT EXISTS server_instructions TEXT;

      CREATE INDEX IF NOT EXISTS idx_servers_last_scanned_at
        ON servers(last_scanned_at);
      CREATE INDEX IF NOT EXISTS idx_servers_connection_status
        ON servers(connection_status) WHERE connection_status IS NOT NULL;

      -- scans: persist pipeline stage completion for operational observability
      -- stages JSON shape: { source_fetched, connection_attempted, connection_succeeded, dependencies_audited }
      ALTER TABLE scans
        ADD COLUMN IF NOT EXISTS stages JSONB;

      -- score_history: track which rules version produced each score
      -- enables attribution: was the score change due to a rule update or server change?
      ALTER TABLE score_history
        ADD COLUMN IF NOT EXISTS rules_version VARCHAR(50);

      -- dependencies: distinguish direct from transitive, track CVE severity
      -- is_direct: D4 (excessive-deps) should count direct deps only — transitive are noise
      -- cve_severity: D1 rule needs CVSS severity to weight critical CVEs vs. low ones
      ALTER TABLE dependencies
        ADD COLUMN IF NOT EXISTS is_direct BOOLEAN NOT NULL DEFAULT true,
        ADD COLUMN IF NOT EXISTS cve_severity VARCHAR(20);
    `,
  },
  {
    id: "005_risk_edges",
    sql: `
      -- risk_edges: cross-server attack path results from RiskMatrixAnalyzer.
      -- Each row represents a dangerous capability edge between two servers
      -- detected by one of the 12 cross-server patterns (P01–P12).
      -- Append-only (ADR-008): never UPDATE. Re-runs insert new rows.
      CREATE TABLE IF NOT EXISTS risk_edges (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        config_id VARCHAR(32) NOT NULL,
        from_server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        to_server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        edge_type VARCHAR(50) NOT NULL,
        pattern_id VARCHAR(10) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        description TEXT NOT NULL,
        owasp_category VARCHAR(50),
        mitre_technique VARCHAR(100),
        detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_risk_edges_from ON risk_edges(from_server_id);
      CREATE INDEX IF NOT EXISTS idx_risk_edges_to ON risk_edges(to_server_id);
      CREATE INDEX IF NOT EXISTS idx_risk_edges_pattern ON risk_edges(pattern_id);
      CREATE INDEX IF NOT EXISTS idx_risk_edges_config ON risk_edges(config_id);
      CREATE INDEX IF NOT EXISTS idx_risk_edges_detected ON risk_edges(detected_at);
    `,
  },
  {
    id: "007_pypi_package_index",
    sql: `
      -- Add partial index on pypi_package to match the existing github_url and npm_package indexes.
      -- Required for upsertServerDedup Priority 3 (PyPI lookup) to use an index scan instead of seq scan.
      CREATE INDEX IF NOT EXISTS idx_servers_pypi_package ON servers(pypi_package) WHERE pypi_package IS NOT NULL;
    `,
  },
  {
    id: "008_unique_canonical_identifiers",
    sql: `
      -- Enforce uniqueness on canonical server identifiers at DB level.
      -- Previously dedup was application-only (upsertServerDedup lookups).
      -- Partial unique indexes: only enforced when the column is NOT NULL,
      -- since multiple servers legitimately have NULL github_url/npm/pypi.
      CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_github_url
        ON servers(github_url) WHERE github_url IS NOT NULL;

      CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_npm_package
        ON servers(npm_package) WHERE npm_package IS NOT NULL;

      CREATE UNIQUE INDEX IF NOT EXISTS uq_servers_pypi_package
        ON servers(pypi_package) WHERE pypi_package IS NOT NULL;
    `,
  },
  {
    id: "006_dynamic_test_results",
    sql: `
      -- dynamic_test_results: one row per DynamicTester.test() execution.
      --
      -- Append-only (ADR-008). Provides:
      --   • Legal/ethical paper trail: consent was obtained before any tool call
      --   • Historical coverage: which servers have been dynamically tested
      --   • Trend analysis: injection vulnerability rate over time
      --   • Operational metrics: tool coverage, timing anomalies
      --
      -- raw_report stores the full DynamicReport JSON for compliance audit export.
      -- It is intentionally not indexed — it exists purely for record-keeping.
      CREATE TABLE IF NOT EXISTS dynamic_test_results (
        id                        UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id                 UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        scan_id                   UUID         REFERENCES scans(id) ON DELETE SET NULL,
        endpoint                  TEXT         NOT NULL,
        consented                 BOOLEAN      NOT NULL DEFAULT false,
        consent_method            VARCHAR(30),
        tested_at                 TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
        elapsed_ms                INTEGER      NOT NULL DEFAULT 0,
        tools_tested              INTEGER      NOT NULL DEFAULT 0,
        tools_skipped             INTEGER      NOT NULL DEFAULT 0,
        output_findings_count     INTEGER      NOT NULL DEFAULT 0,
        injection_vulnerable_count INTEGER     NOT NULL DEFAULT 0,
        output_injection_risk     VARCHAR(20)  NOT NULL DEFAULT 'none',
        injection_vulnerability   VARCHAR(20)  NOT NULL DEFAULT 'none',
        schema_compliance         VARCHAR(10)  NOT NULL DEFAULT 'pass',
        timing_anomalies          INTEGER      NOT NULL DEFAULT 0,
        raw_report                JSONB,
        created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      -- Lookup by server (most common: "has this server been dynamically tested?")
      CREATE INDEX IF NOT EXISTS idx_dtr_server_id
        ON dynamic_test_results(server_id);

      -- Lookup by scan (pipeline: find dynamic result for a given scan)
      CREATE INDEX IF NOT EXISTS idx_dtr_scan_id
        ON dynamic_test_results(scan_id)
        WHERE scan_id IS NOT NULL;

      -- Time-based queries: "tests in the last 30 days"
      CREATE INDEX IF NOT EXISTS idx_dtr_tested_at
        ON dynamic_test_results(tested_at DESC);

      -- Coverage query: "how many consented servers have we found injection vulns in?"
      CREATE INDEX IF NOT EXISTS idx_dtr_consented_vulnerable
        ON dynamic_test_results(consented, injection_vulnerable_count)
        WHERE consented = true;
    `,
  },
  {
    id: "010_attack_chains",
    sql: `
      -- attack_chains: multi-step kill chain synthesis results.
      -- Append-only (ADR-008). Each row is an immutable record of a detected
      -- attack chain across servers in the same client configuration.
      --
      -- chain_id is a deterministic SHA-256 hash of sorted server IDs + template ID.
      -- Re-analyzing the same config with the same template produces the same chain_id,
      -- enabling trend tracking ("was this chain present last scan?").
      CREATE TABLE IF NOT EXISTS attack_chains (
        id                      UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        chain_id                VARCHAR(16)  NOT NULL,
        config_id               VARCHAR(16)  NOT NULL,
        kill_chain_id           VARCHAR(10)  NOT NULL,
        kill_chain_name         TEXT         NOT NULL,
        steps                   JSONB        NOT NULL,
        exploitability_overall  REAL         NOT NULL,
        exploitability_rating   VARCHAR(10)  NOT NULL,
        exploitability_factors  JSONB        NOT NULL,
        narrative               TEXT         NOT NULL,
        mitigations             JSONB        NOT NULL,
        owasp_refs              TEXT[]       NOT NULL DEFAULT '{}',
        mitre_refs              TEXT[]       NOT NULL DEFAULT '{}',
        evidence                JSONB        NOT NULL,
        created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      -- Lookup by config (most common: "what chains exist for this config?")
      CREATE INDEX IF NOT EXISTS idx_ac_config_id
        ON attack_chains(config_id);

      -- Lookup by chain_id (trend: "has this chain appeared before?")
      CREATE INDEX IF NOT EXISTS idx_ac_chain_id
        ON attack_chains(chain_id);

      -- Lookup by kill chain template (analytics: "which templates fire most?")
      CREATE INDEX IF NOT EXISTS idx_ac_kill_chain_id
        ON attack_chains(kill_chain_id);

      -- Time-based queries: "chains detected in the last 30 days"
      CREATE INDEX IF NOT EXISTS idx_ac_created_at
        ON attack_chains(created_at DESC);

      -- Severity filter: "all critical chains"
      CREATE INDEX IF NOT EXISTS idx_ac_rating
        ON attack_chains(exploitability_rating)
        WHERE exploitability_rating IN ('critical', 'high');
    `,
  },
  {
    id: "011_phase1_evidence_profiles",
    sql: `
      -- Phase 1 Evidence Chains + Server Profiles
      --
      -- Problem: The analyzer computes rich evidence chains (source→sink taint flows),
      -- confidence scores (0.0-1.0 with factor breakdowns), and server profiles
      -- (capability classification + threat models), but all of this is discarded
      -- at the pipeline boundary. Only flat evidence text survives to the DB.
      --
      -- This migration adds the persistence layer for Phase 1 analysis features.

      -- ─── 1. Findings: add confidence + evidence_chain ────────────────────────
      --
      -- confidence: REAL [0.05, 0.99] — computed from evidence chain structure.
      --   Full source→sink taint path = 0.70 base. Pattern match only = 0.30 base.
      --   Factors adjust up/down (mitigation present, sanitizer found, etc.).
      --   Default 1.0 for backward compat with pre-Phase 1 findings (no chain = full confidence assumed).
      --
      -- evidence_chain: JSONB — the structured EvidenceChain object.
      --   Contains: links[] (source, propagation, sink, mitigation, impact),
      --   confidence_factors[] (factor name, adjustment, rationale),
      --   threat_reference (CVE/paper backing the finding).
      --   NULL for findings from rules not yet upgraded to evidence chains.
      --   NOT indexed — queried only on server detail page, always filtered by server_id first.

      ALTER TABLE findings
        ADD COLUMN IF NOT EXISTS confidence REAL NOT NULL DEFAULT 1.0
          CHECK (confidence >= 0.0 AND confidence <= 1.0),
        ADD COLUMN IF NOT EXISTS evidence_chain JSONB;

      -- Partial index: only index findings with evidence chains for analytics queries
      -- ("how many findings have structured evidence?", "average confidence of chained findings")
      CREATE INDEX IF NOT EXISTS idx_findings_has_chain
        ON findings(server_id, confidence)
        WHERE evidence_chain IS NOT NULL;

      -- ─── 2. Server Profiles: capability classification + attack surfaces ──────
      --
      -- One row per scan per server. Append-only (ADR-008).
      -- Each profile is the profiler's output for that scan — captures capabilities,
      -- attack surfaces, data flow pairs, and which threats were selected.
      --
      -- Used for:
      --   - Server detail page: "What kind of server is this?"
      --   - Trend analysis: "Has this server's profile changed over time?"
      --   - Aggregate analytics: "What % of servers have code-execution capability?"
      --   - Rule relevance debugging: "Why was rule X skipped for this server?"
      --
      -- profile_type: a short human-readable classification derived from the top
      --   capabilities (e.g., "filesystem + network", "database + credentials").
      --   Stored as TEXT, not enum — profiler may produce new type combinations
      --   as capability patterns expand. Max 200 chars.

      CREATE TABLE IF NOT EXISTS server_profiles (
        id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        server_id       UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        scan_id         UUID         NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        profile_type    VARCHAR(200) NOT NULL,
        capabilities    JSONB        NOT NULL,
        attack_surfaces TEXT[]       NOT NULL DEFAULT '{}',
        data_flow_pairs JSONB        NOT NULL DEFAULT '[]',
        threats         JSONB        NOT NULL DEFAULT '[]',
        summary         TEXT         NOT NULL,
        has_source_code BOOLEAN      NOT NULL DEFAULT false,
        has_connection   BOOLEAN      NOT NULL DEFAULT false,
        has_dependencies BOOLEAN      NOT NULL DEFAULT false,
        tool_count      INTEGER      NOT NULL DEFAULT 0,
        created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      -- Lookup by server: "latest profile for this server"
      CREATE INDEX IF NOT EXISTS idx_sp_server_id
        ON server_profiles(server_id);

      -- Lookup by scan: "which profile was generated for this scan?"
      CREATE INDEX IF NOT EXISTS idx_sp_scan_id
        ON server_profiles(scan_id);

      -- Analytics: "all servers with code-execution capability"
      -- GIN index on capabilities JSONB enables @> containment queries
      CREATE INDEX IF NOT EXISTS idx_sp_capabilities
        ON server_profiles USING gin(capabilities);

      -- Time-series: "profile changes over time"
      CREATE INDEX IF NOT EXISTS idx_sp_created_at
        ON server_profiles(created_at DESC);

      -- Unique constraint: one profile per server per scan
      -- (re-running analysis on the same scan should not create duplicates)
      CREATE UNIQUE INDEX IF NOT EXISTS uq_sp_server_scan
        ON server_profiles(server_id, scan_id);
    `,
  },
  {
    id: "012_compliance_agents",
    sql: `
      -- Compliance Agents (ADR-009 LLM exception, scoped to packages/compliance-agents).
      --
      -- Three append-only tables back the adversarial compliance framework:
      --
      --   1. compliance_findings   — judge-confirmed compliance violations,
      --                              one row per (server, framework, rule, test).
      --   2. compliance_agent_runs — every LLM call (prompt, response, model,
      --                              temperature, latency, cache state) for
      --                              full audit reproducibility.
      --   3. compliance_test_cache — cached per-(server, rule, framework) test
      --                              synthesis output keyed by EvidenceBundle hash.
      --
      -- These tables are independent of the existing findings/scores tables —
      -- they do NOT alter the deterministic vulnerability scoring pipeline.
      -- ADR-008 (append-only) applies: never UPDATE, only INSERT.

      CREATE TABLE IF NOT EXISTS compliance_findings (
        id                 UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        scan_id            UUID         NOT NULL,
        server_id          UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        framework          VARCHAR(40)  NOT NULL,
        rule_id            VARCHAR(120) NOT NULL,
        category_control   VARCHAR(120) NOT NULL,
        severity           VARCHAR(20)  NOT NULL,
        confidence         REAL         NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
        bundle_id          VARCHAR(120) NOT NULL,
        test_id            VARCHAR(120) NOT NULL,
        test_hypothesis    TEXT         NOT NULL,
        judge_rationale    TEXT         NOT NULL,
        evidence_chain     JSONB        NOT NULL,
        remediation        TEXT         NOT NULL,
        created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_cf_scan_id    ON compliance_findings(scan_id);
      CREATE INDEX IF NOT EXISTS idx_cf_server_id  ON compliance_findings(server_id);
      CREATE INDEX IF NOT EXISTS idx_cf_framework  ON compliance_findings(framework);
      CREATE INDEX IF NOT EXISTS idx_cf_rule_id    ON compliance_findings(rule_id);
      CREATE INDEX IF NOT EXISTS idx_cf_severity   ON compliance_findings(severity);
      CREATE INDEX IF NOT EXISTS idx_cf_created_at ON compliance_findings(created_at DESC);

      CREATE TABLE IF NOT EXISTS compliance_agent_runs (
        id              UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        scan_id         UUID         NOT NULL,
        server_id       UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        rule_id         VARCHAR(120) NOT NULL,
        framework       VARCHAR(40)  NOT NULL,
        phase           VARCHAR(20)  NOT NULL,
        cache_key       VARCHAR(200) NOT NULL,
        model           VARCHAR(80)  NOT NULL,
        temperature     REAL         NOT NULL,
        max_tokens      INTEGER      NOT NULL,
        prompt          JSONB        NOT NULL,
        response        JSONB        NOT NULL,
        cached          BOOLEAN      NOT NULL DEFAULT false,
        duration_ms     INTEGER      NOT NULL DEFAULT 0,
        input_tokens    INTEGER,
        output_tokens   INTEGER,
        created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_car_scan_id    ON compliance_agent_runs(scan_id);
      CREATE INDEX IF NOT EXISTS idx_car_server_id  ON compliance_agent_runs(server_id);
      CREATE INDEX IF NOT EXISTS idx_car_rule_id    ON compliance_agent_runs(rule_id);
      CREATE INDEX IF NOT EXISTS idx_car_cache_key  ON compliance_agent_runs(cache_key);
      CREATE INDEX IF NOT EXISTS idx_car_created_at ON compliance_agent_runs(created_at DESC);

      CREATE TABLE IF NOT EXISTS compliance_test_cache (
        id            UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
        cache_key     VARCHAR(200) NOT NULL UNIQUE,
        server_id     UUID         NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
        rule_id       VARCHAR(120) NOT NULL,
        framework     VARCHAR(40)  NOT NULL,
        bundle_id     VARCHAR(120) NOT NULL,
        content_hash  VARCHAR(64)  NOT NULL,
        tests         JSONB        NOT NULL,
        model         VARCHAR(80)  NOT NULL,
        created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_ctc_server_id    ON compliance_test_cache(server_id);
      CREATE INDEX IF NOT EXISTS idx_ctc_rule_id      ON compliance_test_cache(rule_id);
      CREATE INDEX IF NOT EXISTS idx_ctc_content_hash ON compliance_test_cache(content_hash);
    `,
  },
  {
    id: "013_engine_v2_shadow_scores",
    sql: `
      -- Phase 0, Chunk 0.2 — engine_v2 shadow score.
      --
      -- Each rule now carries an optional \`engine_v2: boolean\` flag in its
      -- YAML metadata (default false). When true, findings from that rule are
      -- counted toward a SECOND total score, stored here as total_score_v2,
      -- alongside the existing total_score. Until at least one rule is
      -- flipped to engine_v2, total_score_v2 is NULL.
      --
      -- This lets Phase 1 migrate rules one at a time and observe the v2
      -- score drift against production without changing any public-facing
      -- number. See docs/standards/rule-standard-v2.md.
      --
      -- ADR-008 compliance: both columns are NULL by default and only
      -- populated by new INSERTs. Historical rows remain untouched.

      ALTER TABLE scores
        ADD COLUMN IF NOT EXISTS total_score_v2 INTEGER NULL
          CHECK (total_score_v2 IS NULL OR (total_score_v2 >= 0 AND total_score_v2 <= 100));

      -- Technique attribution map for the v2 findings that contributed to
      -- total_score_v2. Shape: {"C1": "ast-taint", "F1": "capability-graph", ...}
      ALTER TABLE scores
        ADD COLUMN IF NOT EXISTS techniques_v2 JSONB NULL;

      -- Queries that filter by v2 readiness should use a partial index so we
      -- don't bloat the B-tree with the NULL majority during the rollout.
      CREATE INDEX IF NOT EXISTS idx_scores_total_score_v2
        ON scores(total_score_v2)
        WHERE total_score_v2 IS NOT NULL;
    `,
  },
];

export async function migrate(connectionString: string): Promise<void> {
  const isRemote =
    connectionString &&
    !connectionString.includes("localhost") &&
    !connectionString.includes("127.0.0.1");
  const client = new pg.Client({
    connectionString,
    ssl: isRemote ? { rejectUnauthorized: false } : false,
  });
  await client.connect();

  try {
    // Ensure migrations table exists
    await client.query(`
      CREATE TABLE IF NOT EXISTS _migrations (
        id VARCHAR(100) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const applied = await client.query("SELECT id FROM _migrations");
    const appliedIds = new Set(applied.rows.map((r) => r.id));

    for (const migration of MIGRATIONS) {
      if (appliedIds.has(migration.id)) {
        logger.info({ migration: migration.id }, "Migration already applied");
        continue;
      }

      logger.info({ migration: migration.id }, "Applying migration");
      await client.query("BEGIN");
      try {
        await client.query(migration.sql);
        await client.query("INSERT INTO _migrations (id) VALUES ($1)", [
          migration.id,
        ]);
        await client.query("COMMIT");
        logger.info({ migration: migration.id }, "Migration applied");
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      }
    }

    logger.info("All migrations applied");
  } finally {
    await client.end();
  }
}

// CLI entrypoint — only runs when executed directly (not when imported as a module)
if (
  process.argv[1] &&
  (process.argv[1].endsWith("migrate.js") ||
    process.argv[1].endsWith("migrate.ts"))
) {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    logger.error("DATABASE_URL not set");
    process.exit(1);
  }
  migrate(dbUrl)
    .then(() => process.exit(0))
    .catch((err) => {
      logger.error(err, "Migration failed");
      process.exit(1);
    });
}
