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
];

export async function migrate(connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString });
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
