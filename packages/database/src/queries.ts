import pg from "pg";
import type {
  ComplianceAgentRun,
  ComplianceFindingRecord,
  ComplianceFrameworkId,
  ComplianceTestCache,
  DiscoveredServer,
  FindingInput,
  Server,
  ServerListQuery,
} from "./schemas.js";

export class DatabaseQueries {
  constructor(private pool: pg.Pool) {}

  // ─── Server Operations ─────────────────────────────────────────────────────

  async upsertServer(discovered: DiscoveredServer): Promise<string> {
    const slug = this.slugify(discovered.name);

    // Extract github_stars from raw_metadata if available
    const githubStars = this._extractGithubStars(discovered.raw_metadata);

    const result = await this.pool.query(
      `INSERT INTO servers (name, slug, description, author, github_url, npm_package, pypi_package, category, language, license, github_stars)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (slug) DO UPDATE SET
         description = COALESCE(EXCLUDED.description, servers.description),
         author = COALESCE(EXCLUDED.author, servers.author),
         github_url = COALESCE(EXCLUDED.github_url, servers.github_url),
         npm_package = COALESCE(EXCLUDED.npm_package, servers.npm_package),
         pypi_package = COALESCE(EXCLUDED.pypi_package, servers.pypi_package),
         category = COALESCE(EXCLUDED.category, servers.category),
         language = COALESCE(EXCLUDED.language, servers.language),
         license = COALESCE(EXCLUDED.license, servers.license),
         github_stars = COALESCE(EXCLUDED.github_stars, servers.github_stars),
         updated_at = NOW()
       RETURNING id`,
      [
        discovered.name,
        slug,
        discovered.description,
        discovered.author,
        discovered.github_url,
        discovered.npm_package,
        discovered.pypi_package,
        discovered.category,
        discovered.language,
        discovered.license,
        githubStars,
      ]
    );

    const serverId = result.rows[0].id;

    // Record source
    await this.pool.query(
      `INSERT INTO sources (server_id, source_name, source_url, external_id, raw_metadata)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (server_id, source_name, external_id) DO UPDATE SET
         raw_metadata = EXCLUDED.raw_metadata,
         last_synced = NOW()`,
      [
        serverId,
        discovered.source_name,
        discovered.source_url,
        discovered.external_id,
        JSON.stringify(discovered.raw_metadata),
      ]
    );

    return serverId;
  }

  async findServerByGithubUrl(url: string): Promise<Server | null> {
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE github_url = $1 LIMIT 1",
      [url]
    );
    return result.rows[0] || null;
  }

  async findServerByNpmPackage(pkg: string): Promise<Server | null> {
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE npm_package = $1 LIMIT 1",
      [pkg]
    );
    return result.rows[0] || null;
  }

  async findServerByPypiPackage(pkg: string): Promise<Server | null> {
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE pypi_package = $1 LIMIT 1",
      [pkg]
    );
    return result.rows[0] || null;
  }

  /**
   * Upsert with canonical deduplication priority:
   *   github_url → npm_package → pypi_package → slug (new server)
   *
   * When an existing record is found by a canonical identifier, the existing
   * record is enriched with any non-null fields from the new discovery
   * (COALESCE semantics: never overwrites data we already have).
   *
   * Returns { id, is_new } — is_new=false means an existing record was enriched.
   *
   * This is the correct method for crawlAndPersist. The legacy upsertServer()
   * (slug-only conflict) is kept for backward compatibility and as the final
   * fallback in this chain.
   */
  async upsertServerDedup(
    discovered: DiscoveredServer
  ): Promise<{ id: string; is_new: boolean }> {
    // Normalize canonical identifiers before any lookup or insert.
    // This ensures "https://github.com/Foo/Bar.git" and "https://github.com/foo/bar"
    // resolve to the same row — matching the in-memory dedup key logic.
    if (discovered.github_url) {
      discovered = {
        ...discovered,
        github_url: discovered.github_url.toLowerCase().replace(/\.git$/, "").replace(/\/$/, ""),
      };
    }
    if (discovered.npm_package) {
      discovered = { ...discovered, npm_package: discovered.npm_package.toLowerCase() };
    }
    if (discovered.pypi_package) {
      discovered = { ...discovered, pypi_package: discovered.pypi_package.toLowerCase() };
    }

    // Priority 1: canonical GitHub URL — most reliable cross-source identifier
    if (discovered.github_url) {
      const existing = await this.findServerByGithubUrl(discovered.github_url);
      if (existing) {
        await this._enrichServer(existing.id, discovered);
        return { id: existing.id, is_new: false };
      }
    }

    // Priority 2: npm package name
    if (discovered.npm_package) {
      const existing = await this.findServerByNpmPackage(discovered.npm_package);
      if (existing) {
        await this._enrichServer(existing.id, discovered);
        return { id: existing.id, is_new: false };
      }
    }

    // Priority 3: PyPI package name
    if (discovered.pypi_package) {
      const existing = await this.findServerByPypiPackage(discovered.pypi_package);
      if (existing) {
        await this._enrichServer(existing.id, discovered);
        return { id: existing.id, is_new: false };
      }
    }

    // No canonical match — insert as new server (slug-based conflict resolution)
    const id = await this.upsertServer(discovered);
    return { id, is_new: true };
  }

  /**
   * Enrich an existing server record with data from a new discovery.
   * Uses COALESCE: fills null fields, never overwrites data we already have.
   * Also upserts the source record so we track all registries listing this server.
   */
  private async _enrichServer(
    serverId: string,
    discovered: DiscoveredServer
  ): Promise<void> {
    const githubStars = this._extractGithubStars(discovered.raw_metadata);

    await this.pool.query(
      `UPDATE servers SET
         description  = COALESCE(servers.description,  $2),
         author       = COALESCE(servers.author,       $3),
         github_url   = COALESCE(servers.github_url,   $4),
         npm_package  = COALESCE(servers.npm_package,  $5),
         pypi_package = COALESCE(servers.pypi_package, $6),
         category     = COALESCE(servers.category,     $7),
         language     = COALESCE(servers.language,     $8),
         license      = COALESCE(servers.license,      $9),
         github_stars = COALESCE($10, servers.github_stars),
         updated_at   = NOW()
       WHERE id = $1`,
      [
        serverId,
        discovered.description,
        discovered.author,
        discovered.github_url,
        discovered.npm_package,
        discovered.pypi_package,
        discovered.category,
        discovered.language,
        discovered.license,
        githubStars,
      ]
    );

    // Record this source occurrence even though the server already existed
    await this.pool.query(
      `INSERT INTO sources (server_id, source_name, source_url, external_id, raw_metadata)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (server_id, source_name, external_id) DO UPDATE SET
         raw_metadata = EXCLUDED.raw_metadata,
         last_synced  = NOW()`,
      [
        serverId,
        discovered.source_name,
        discovered.source_url,
        discovered.external_id,
        JSON.stringify(discovered.raw_metadata),
      ]
    );
  }

  /**
   * Persist a crawl run summary for historical yield tracking.
   * Append-only — never updated after insert (ADR-008).
   */
  async insertCrawlRun(run: {
    started_at: Date;
    completed_at: Date;
    total_discovered: number;
    new_to_db: number;
    enriched_existing: number;
    persist_errors: number;
    per_source: Array<{
      source: string;
      found: number;
      unique: number;
      duplicates: number;
      errors: number;
      elapsed_ms: number;
    }>;
    data_quality: {
      with_github_url: number;
      with_npm_package: number;
      with_description: number;
      with_category: number;
    };
    elapsed_ms: number;
  }): Promise<string> {
    const result = await this.pool.query(
      `INSERT INTO crawl_runs
         (started_at, completed_at, total_discovered, new_to_db, enriched_existing,
          persist_errors, per_source, data_quality, elapsed_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [
        run.started_at,
        run.completed_at,
        run.total_discovered,
        run.new_to_db,
        run.enriched_existing,
        run.persist_errors,
        JSON.stringify(run.per_source),
        JSON.stringify(run.data_quality),
        run.elapsed_ms,
      ]
    );
    return result.rows[0].id;
  }

  async findServerBySlug(slug: string): Promise<Server | null> {
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE slug = $1 LIMIT 1",
      [slug]
    );
    return result.rows[0] || null;
  }

  async searchServers(query: ServerListQuery) {
    const conditions: string[] = [];
    const params: unknown[] = [];
    let paramIdx = 1;

    if (query.q) {
      conditions.push(
        `(search_vector @@ plainto_tsquery('english', $${paramIdx}) OR name ILIKE $${paramIdx + 1})`
      );
      params.push(query.q, `%${query.q}%`);
      paramIdx += 2;
    }

    if (query.category) {
      conditions.push(`category = $${paramIdx}`);
      params.push(query.category);
      paramIdx++;
    }

    if (query.min_score !== undefined) {
      conditions.push(`latest_score >= $${paramIdx}`);
      params.push(query.min_score);
      paramIdx++;
    }

    if (query.max_score !== undefined) {
      conditions.push(`latest_score <= $${paramIdx}`);
      params.push(query.max_score);
      paramIdx++;
    }

    const where =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const sortColumn: Record<string, string> = {
      score: "latest_score",
      name: "name",
      stars: "github_stars",
      updated: "updated_at",
      downloads: "npm_downloads",
    };
    const sort = sortColumn[query.sort] || "latest_score";
    const order = query.order === "asc" ? "ASC" : "DESC";
    const offset = (query.page - 1) * query.limit;

    const countResult = await this.pool.query(
      `SELECT COUNT(*) as total FROM servers ${where}`,
      params
    );

    const dataResult = await this.pool.query(
      `SELECT s.*,
              COALESCE(
                (SELECT array_agg(DISTINCT src.source_name ORDER BY src.source_name)
                 FROM sources src WHERE src.server_id = s.id),
                '{}'
              ) AS source_names
       FROM servers s ${where}
       ORDER BY ${sort} ${order} NULLS LAST
       LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
      [...params, query.limit, offset]
    );

    return {
      servers: dataResult.rows as (Server & { source_names: string[] })[],
      total: parseInt(countResult.rows[0].total, 10),
      page: query.page,
      limit: query.limit,
    };
  }

  // ─── Tool Operations ───────────────────────────────────────────────────────

  async upsertTools(
    serverId: string,
    tools: Array<{
      name: string;
      description: string | null;
      input_schema: Record<string, unknown> | null;
    }>
  ): Promise<void> {
    if (tools.length === 0) return;

    for (const tool of tools) {
      const result = await this.pool.query(
        `INSERT INTO tools (server_id, name, description, input_schema)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (server_id, name) DO UPDATE SET
           description = EXCLUDED.description,
           input_schema = EXCLUDED.input_schema,
           updated_at = NOW()
         RETURNING id`,
        [serverId, tool.name, tool.description, JSON.stringify(tool.input_schema)]
      );

      // Extract and store parameters from input_schema
      if (tool.input_schema?.properties) {
        const toolId = result.rows[0].id;
        const required = (tool.input_schema.required as string[]) || [];
        const properties = tool.input_schema.properties as Record<
          string,
          Record<string, unknown>
        >;

        for (const [paramName, paramDef] of Object.entries(properties)) {
          await this.pool.query(
            `INSERT INTO parameters (tool_id, name, type, required, description, constraints)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tool_id, name) DO UPDATE SET
               type = EXCLUDED.type,
               required = EXCLUDED.required,
               description = EXCLUDED.description,
               constraints = EXCLUDED.constraints`,
            [
              toolId,
              paramName,
              (paramDef.type as string) || "string",
              required.includes(paramName),
              paramDef.description || null,
              JSON.stringify(paramDef),
            ]
          );
        }
      }
    }

    // Denormalize tool_count on the servers table
    await this.pool.query(
      "UPDATE servers SET tool_count = $1 WHERE id = $2",
      [tools.length, serverId]
    );
  }

  async getToolsForServer(serverId: string) {
    const rows = (
      await this.pool.query(
        "SELECT * FROM tools WHERE server_id = $1 ORDER BY name",
        [serverId]
      )
    ).rows;

    // Keep tool_count denormalized on servers
    if (rows.length > 0) {
      await this.pool.query(
        "UPDATE servers SET tool_count = $1 WHERE id = $2",
        [rows.length, serverId]
      );
    }

    return rows;
  }

  // ─── Scan Operations ───────────────────────────────────────────────────────

  async createScan(
    serverId: string,
    rulesVersion: string
  ): Promise<string> {
    const result = await this.pool.query(
      `INSERT INTO scans (server_id, status, rules_version)
       VALUES ($1, 'running', $2) RETURNING id`,
      [serverId, rulesVersion]
    );
    return result.rows[0].id;
  }

  async completeScan(
    scanId: string,
    findingsCount: number,
    error: string | null = null,
    stages?: {
      source_fetched: boolean;
      connection_attempted: boolean;
      connection_succeeded: boolean;
      dependencies_audited: boolean;
    }
  ): Promise<void> {
    await this.pool.query(
      `UPDATE scans SET
         status = $1,
         completed_at = NOW(),
         findings_count = $2,
         error = $3,
         stages = $4
       WHERE id = $5`,
      [error ? "failed" : "completed", findingsCount, error, stages ? JSON.stringify(stages) : null, scanId]
    );

    // Denormalize last_scanned_at onto the server row for fast incremental queries
    await this.pool.query(
      `UPDATE servers SET last_scanned_at = NOW() WHERE id = (SELECT server_id FROM scans WHERE id = $1)`,
      [scanId]
    );
  }

  /**
   * Persist connection data discovered during Stage 3+4 of the scan pipeline.
   * Called immediately after the MCPConnector enumerate() attempt completes.
   * - endpoint_url: cached so future scans skip re-scanning raw_metadata sources
   * - connection_status: surfaces health in web UI
   * - server_version / server_instructions: H2 rule data — persisted for historical analysis
   * - tool_count: denormalized after upsertTools() for fast UI sort/filter
   */
  async updateServerConnectionData(
    serverId: string,
    data: {
      endpoint_url?: string | null;
      connection_status: "success" | "failed" | "timeout" | "no_endpoint";
      server_version?: string | null;
      server_instructions?: string | null;
    }
  ): Promise<void> {
    await this.pool.query(
      `UPDATE servers SET
         endpoint_url = COALESCE($2, endpoint_url),
         connection_status = $3,
         server_version = COALESCE($4, server_version),
         server_instructions = COALESCE($5, server_instructions),
         updated_at = NOW()
       WHERE id = $1`,
      [
        serverId,
        data.endpoint_url ?? null,
        data.connection_status,
        data.server_version ?? null,
        data.server_instructions ?? null,
      ]
    );
  }

  // ─── Finding Operations ────────────────────────────────────────────────────

  async insertFindings(
    serverId: string,
    scanId: string,
    findings: FindingInput[]
  ): Promise<void> {
    for (const finding of findings) {
      await this.pool.query(
        `INSERT INTO findings (server_id, scan_id, rule_id, severity, evidence, remediation, owasp_category, mitre_technique, confidence, evidence_chain)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          serverId,
          scanId,
          finding.rule_id,
          finding.severity,
          finding.evidence,
          finding.remediation,
          finding.owasp_category,
          finding.mitre_technique,
          finding.confidence ?? 1.0,
          finding.evidence_chain ? JSON.stringify(finding.evidence_chain) : null,
        ]
      );
    }
  }

  async getFindingsForServer(serverId: string) {
    return (
      await this.pool.query(
        `SELECT f.* FROM findings f
         JOIN scans s ON f.scan_id = s.id
         WHERE f.server_id = $1
         AND s.id = (SELECT id FROM scans WHERE server_id = $1 AND status = 'completed' ORDER BY completed_at DESC LIMIT 1)
         ORDER BY
           CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
        [serverId]
      )
    ).rows;
  }

  // ─── Score Operations ──────────────────────────────────────────────────────

  async insertScore(score: {
    server_id: string;
    scan_id: string;
    total_score: number;
    code_score: number;
    deps_score: number;
    config_score: number;
    description_score: number;
    behavior_score: number;
    owasp_coverage: Record<string, boolean>;
    rules_version?: string;
    // Phase 0, chunk 0.2 — shadow score from engine_v2 rules only.
    total_score_v2?: number | null;
    techniques_v2?: Record<string, string> | null;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO scores (server_id, scan_id, total_score, code_score, deps_score, config_score, description_score, behavior_score, owasp_coverage, total_score_v2, techniques_v2)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (server_id, scan_id) DO UPDATE SET
         total_score = EXCLUDED.total_score,
         code_score = EXCLUDED.code_score,
         deps_score = EXCLUDED.deps_score,
         config_score = EXCLUDED.config_score,
         description_score = EXCLUDED.description_score,
         behavior_score = EXCLUDED.behavior_score,
         owasp_coverage = EXCLUDED.owasp_coverage,
         total_score_v2 = EXCLUDED.total_score_v2,
         techniques_v2 = EXCLUDED.techniques_v2`,
      [
        score.server_id,
        score.scan_id,
        score.total_score,
        score.code_score,
        score.deps_score,
        score.config_score,
        score.description_score,
        score.behavior_score,
        JSON.stringify(score.owasp_coverage),
        score.total_score_v2 ?? null,
        score.techniques_v2 ? JSON.stringify(score.techniques_v2) : null,
      ]
    );

    // Update server's latest score
    await this.pool.query(
      "UPDATE servers SET latest_score = $1, updated_at = NOW() WHERE id = $2",
      [score.total_score, score.server_id]
    );

    // Record in history
    const findingsCount = await this.pool.query(
      "SELECT COUNT(*) as cnt FROM findings WHERE server_id = $1 AND scan_id = $2",
      [score.server_id, score.scan_id]
    );

    await this.pool.query(
      `INSERT INTO score_history (server_id, score, findings_count, rules_version)
       VALUES ($1, $2, $3, $4)`,
      [score.server_id, score.total_score, parseInt(findingsCount.rows[0].cnt, 10), score.rules_version ?? null]
    );
  }

  async getLatestScoreForServer(serverId: string): Promise<{
    total_score: number;
    code_score: number;
    deps_score: number;
    config_score: number;
    description_score: number;
    behavior_score: number;
    owasp_coverage: Record<string, boolean>;
  } | null> {
    const result = await this.pool.query(
      `SELECT total_score, code_score, deps_score, config_score, description_score, behavior_score, owasp_coverage
       FROM scores
       WHERE server_id = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [serverId]
    );
    return result.rows[0] ?? null;
  }

  async getScoreHistory(serverId: string) {
    return (
      await this.pool.query(
        "SELECT * FROM score_history WHERE server_id = $1 ORDER BY recorded_at DESC",
        [serverId]
      )
    ).rows;
  }

  // ─── Ecosystem Stats ──────────────────────────────────────────────────────

  async getEcosystemStats() {
    const [total, scanned, avgScore, categories, severities, distribution, multiSource, uniqueIdent] =
      await Promise.all([
        this.pool.query("SELECT COUNT(*) as cnt FROM servers"),
        this.pool.query(
          "SELECT COUNT(*) as cnt FROM servers WHERE latest_score IS NOT NULL"
        ),
        this.pool.query(
          "SELECT AVG(latest_score) as avg FROM servers WHERE latest_score IS NOT NULL"
        ),
        this.pool.query(
          "SELECT category, COUNT(*) as cnt FROM servers WHERE category IS NOT NULL GROUP BY category ORDER BY cnt DESC"
        ),
        this.pool.query(
          `SELECT severity, COUNT(*) as cnt FROM findings f
           JOIN scans s ON f.scan_id = s.id
           WHERE s.status = 'completed'
           GROUP BY severity`
        ),
        this.pool.query(
          `SELECT
             CASE
               WHEN latest_score >= 80 THEN '80-100'
               WHEN latest_score >= 60 THEN '60-79'
               WHEN latest_score >= 40 THEN '40-59'
               WHEN latest_score >= 20 THEN '20-39'
               ELSE '0-19'
             END AS range,
             COUNT(*) AS count
           FROM servers
           WHERE latest_score IS NOT NULL
           GROUP BY range
           ORDER BY range DESC`
        ),
        // Servers confirmed from 2+ distinct sources (high-confidence unique)
        this.pool.query(
          `SELECT COUNT(*) as cnt FROM (
             SELECT server_id FROM sources GROUP BY server_id HAVING COUNT(DISTINCT source_name) >= 2
           ) t`
        ),
        // Servers with at least one canonical identifier (not slug-only)
        this.pool.query(
          `SELECT COUNT(*) as cnt FROM servers
           WHERE github_url IS NOT NULL OR npm_package IS NOT NULL OR pypi_package IS NOT NULL`
        ),
      ]);

    return {
      total_servers: parseInt(total.rows[0].cnt, 10),
      total_scanned: parseInt(scanned.rows[0].cnt, 10),
      average_score: Math.round(parseFloat(avgScore.rows[0].avg) ?? 0),
      category_breakdown: Object.fromEntries(
        categories.rows.map((r) => [r.category, parseInt(r.cnt, 10)])
      ),
      severity_breakdown: Object.fromEntries(
        severities.rows.map((r) => [r.severity, parseInt(r.cnt, 10)])
      ),
      score_distribution: distribution.rows.map((r) => ({
        range: r.range as string,
        count: parseInt(r.count, 10),
      })),
      multi_source_count: parseInt(multiSource.rows[0]?.cnt ?? '0', 10),
      unique_with_identifier: parseInt(uniqueIdent.rows[0]?.cnt ?? '0', 10),
    };
  }

  /**
   * Detailed dedup quality report for admin/operational visibility.
   * Shows how well canonical identifiers are populated across the server table,
   * and how many servers are confirmed by multiple independent sources.
   */
  async getDedupStats(): Promise<{
    total_servers: number;
    with_github: number;
    with_npm: number;
    with_pypi: number;
    multi_source: number;
    slug_only: number;
  }> {
    const [total, withGithub, withNpm, withPypi, multiSource] = await Promise.all([
      this.pool.query('SELECT COUNT(*) as cnt FROM servers'),
      this.pool.query('SELECT COUNT(*) as cnt FROM servers WHERE github_url IS NOT NULL'),
      this.pool.query('SELECT COUNT(*) as cnt FROM servers WHERE npm_package IS NOT NULL'),
      this.pool.query('SELECT COUNT(*) as cnt FROM servers WHERE pypi_package IS NOT NULL'),
      this.pool.query(
        `SELECT COUNT(*) as cnt FROM (
           SELECT server_id FROM sources GROUP BY server_id HAVING COUNT(DISTINCT source_name) >= 2
         ) t`
      ),
    ]);
    const totalN = parseInt(total.rows[0].cnt, 10);
    const withAny = await this.pool.query(
      'SELECT COUNT(*) as cnt FROM servers WHERE github_url IS NOT NULL OR npm_package IS NOT NULL OR pypi_package IS NOT NULL'
    );
    return {
      total_servers: totalN,
      with_github: parseInt(withGithub.rows[0].cnt, 10),
      with_npm: parseInt(withNpm.rows[0].cnt, 10),
      with_pypi: parseInt(withPypi.rows[0].cnt, 10),
      multi_source: parseInt(multiSource.rows[0].cnt, 10),
      slug_only: totalN - parseInt(withAny.rows[0].cnt, 10),
    };
  }

  // ─── Servers needing scan ─────────────────────────────────────────────────

  async getUnscannedServers(limit: number = 100) {
    return (
      await this.pool.query(
        `SELECT s.* FROM servers s
         WHERE NOT EXISTS (SELECT 1 FROM scans sc WHERE sc.server_id = s.id AND sc.status = 'completed')
         ORDER BY s.github_stars DESC NULLS LAST
         LIMIT $1`,
        [limit]
      )
    ).rows as Server[];
  }

  async getServersNeedingRescan(daysSinceLastScan: number = 7, limit: number = 100) {
    return (
      await this.pool.query(
        `SELECT s.* FROM servers s
         WHERE s.id NOT IN (
           SELECT server_id FROM scans
           WHERE status = 'completed' AND completed_at > NOW() - INTERVAL '1 day' * $1
         )
         ORDER BY s.github_stars DESC NULLS LAST
         LIMIT $2`,
        [daysSinceLastScan, limit]
      )
    ).rows as Server[];
  }

  async getFailedServers(limit: number = 100) {
    return (
      await this.pool.query(
        `SELECT s.* FROM servers s
         WHERE EXISTS (
           SELECT 1 FROM scans sc
           WHERE sc.server_id = s.id
             AND sc.status = 'failed'
             AND sc.id = (
               SELECT id FROM scans WHERE server_id = s.id ORDER BY started_at DESC LIMIT 1
             )
         )
         ORDER BY s.github_stars DESC NULLS LAST
         LIMIT $1`,
        [limit]
      )
    ).rows as Server[];
  }

  async getServersNeedingEnumeration(limit: number = 100) {
    return (
      await this.pool.query(
        `SELECT * FROM servers
         WHERE connection_status IS NULL
         ORDER BY github_stars DESC NULLS LAST
         LIMIT $1`,
        [limit]
      )
    ).rows as Server[];
  }

  async getAllServers(limit: number = 100) {
    return (
      await this.pool.query(
        `SELECT * FROM servers ORDER BY github_stars DESC NULLS LAST LIMIT $1`,
        [limit]
      )
    ).rows as Server[];
  }

  // ─── Scorer Support Queries ───────────────────────────────────────────────

  /** Returns the latest completed (scan_id, server_id) pair per server, for scoring. */
  async getServersWithCompletedScans(limit: number = 1000): Promise<Array<{ server_id: string; scan_id: string }>> {
    return (
      await this.pool.query(
        `SELECT DISTINCT ON (sc.server_id) sc.server_id, sc.id AS scan_id
         FROM scans sc
         WHERE sc.status = 'completed'
         ORDER BY sc.server_id, sc.completed_at DESC
         LIMIT $1`,
        [limit]
      )
    ).rows;
  }

  /** Returns all findings for a specific scan, for score recomputation. */
  async getFindingsByScanId(scanId: string) {
    return (
      await this.pool.query(
        `SELECT * FROM findings WHERE scan_id = $1`,
        [scanId]
      )
    ).rows as import("./schemas.js").Finding[];
  }

  // ─── Scanner Support Queries ──────────────────────────────────────────────

  async getServerById(id: string): Promise<Server | null> {
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE id = $1 LIMIT 1",
      [id]
    );
    return result.rows[0] || null;
  }

  /**
   * Return multiple servers by their UUIDs.
   * Used by the risk-matrix API endpoint to load a set of servers for
   * cross-server capability analysis (P01–P12 patterns).
   * IDs not found in the DB are silently omitted.
   */
  async getServersByIds(ids: string[]): Promise<Server[]> {
    if (ids.length === 0) return [];
    // Parameterized using ANY($1::uuid[]) — safe against injection
    const result = await this.pool.query(
      "SELECT * FROM servers WHERE id = ANY($1::uuid[]) ORDER BY name",
      [ids]
    );
    return result.rows;
  }

  /**
   * Return all source records for a server, including raw_metadata.
   * Used by the scanner to discover live HTTP endpoints embedded in
   * raw_metadata by PulseMCP, Smithery, Glama, and other registries.
   */
  async getServerSources(serverId: string): Promise<
    Array<{
      source_name: string;
      source_url: string | null;
      raw_metadata: Record<string, unknown>;
    }>
  > {
    const result = await this.pool.query(
      "SELECT source_name, source_url, raw_metadata FROM sources WHERE server_id = $1",
      [serverId]
    );
    return result.rows;
  }

  /**
   * Upsert enriched dependencies for a server.
   * Called after the OSV CVE audit step in the scan pipeline.
   * Uses UNIQUE(server_id, name, ecosystem) conflict resolution.
   */
  async upsertDependencies(
    serverId: string,
    deps: Array<{
      name: string;
      version: string | null;
      ecosystem: string;
      has_known_cve: boolean;
      cve_ids: string[];
      last_updated: Date | null;
      is_direct?: boolean;
      cve_severity?: string | null;
    }>
  ): Promise<void> {
    for (const dep of deps) {
      await this.pool.query(
        `INSERT INTO dependencies (server_id, name, version, ecosystem, has_known_cve, cve_ids, last_updated, is_direct, cve_severity)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (server_id, name, ecosystem) DO UPDATE SET
           version = COALESCE(EXCLUDED.version, dependencies.version),
           has_known_cve = EXCLUDED.has_known_cve,
           cve_ids = EXCLUDED.cve_ids,
           last_updated = COALESCE(EXCLUDED.last_updated, dependencies.last_updated),
           is_direct = EXCLUDED.is_direct,
           cve_severity = COALESCE(EXCLUDED.cve_severity, dependencies.cve_severity)`,
        [
          serverId,
          dep.name,
          dep.version,
          dep.ecosystem,
          dep.has_known_cve,
          dep.cve_ids,
          dep.last_updated,
          dep.is_direct ?? true,
          dep.cve_severity ?? null,
        ]
      );
    }
  }

  // ─── Risk Matrix Queries ──────────────────────────────────────────────────

  /**
   * Load all scored servers with their tools for cross-server risk analysis.
   * Returns servers that have at least one completed scan (have a latest_score).
   * Used by RiskMatrixAnalyzer to build the capability graph.
   */
  async getServersWithTools(limit: number = 5000): Promise<
    Array<{
      server_id: string;
      server_name: string;
      server_slug: string;
      latest_score: number | null;
      category: string | null;
      tools: Array<{ name: string; description: string | null; capability_tags: string[] }>;
    }>
  > {
    const serversResult = await this.pool.query(
      `SELECT id, name, slug, latest_score, category
       FROM servers
       WHERE latest_score IS NOT NULL
       ORDER BY latest_score ASC
       LIMIT $1`,
      [limit]
    );

    if (serversResult.rows.length === 0) return [];

    const serverIds = serversResult.rows.map((r: { id: string }) => r.id);
    const toolsResult = await this.pool.query(
      `SELECT server_id, name, description, capability_tags
       FROM tools
       WHERE server_id = ANY($1::uuid[])`,
      [serverIds]
    );

    const toolsByServer = new Map<string, Array<{ name: string; description: string | null; capability_tags: string[] }>>();
    for (const tool of toolsResult.rows) {
      const existing = toolsByServer.get(tool.server_id) ?? [];
      existing.push({
        name: tool.name,
        description: tool.description,
        capability_tags: tool.capability_tags ?? [],
      });
      toolsByServer.set(tool.server_id, existing);
    }

    return serversResult.rows.map((s: { id: string; name: string; slug: string; latest_score: number | null; category: string | null }) => ({
      server_id: s.id,
      server_name: s.name,
      server_slug: s.slug,
      latest_score: s.latest_score,
      category: s.category,
      tools: toolsByServer.get(s.id) ?? [],
    }));
  }

  /**
   * Persist cross-server risk edges detected by RiskMatrixAnalyzer.
   * config_id is a hash of the server IDs in the analyzed set.
   */
  async upsertRiskEdges(
    configId: string,
    edges: Array<{
      from_server_id: string;
      to_server_id: string;
      edge_type: string;
      pattern_id: string;
      severity: string;
      description: string;
      owasp_category?: string | null;
      mitre_technique?: string | null;
    }>
  ): Promise<void> {
    for (const edge of edges) {
      await this.pool.query(
        `INSERT INTO risk_edges (config_id, from_server_id, to_server_id, edge_type, pattern_id, severity, description, owasp_category, mitre_technique)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          configId,
          edge.from_server_id,
          edge.to_server_id,
          edge.edge_type,
          edge.pattern_id,
          edge.severity,
          edge.description,
          edge.owasp_category ?? null,
          edge.mitre_technique ?? null,
        ]
      );
    }
  }

  /**
   * Fetch all risk edges that involve a given server (as source or target).
   * Joins with the servers table to return peer server name and slug.
   */
  async getRiskEdgesForServer(serverId: string): Promise<
    Array<{
      id: string;
      config_id: string;
      from_server_id: string;
      from_server_name: string;
      from_server_slug: string;
      to_server_id: string;
      to_server_name: string;
      to_server_slug: string;
      edge_type: string;
      pattern_id: string;
      severity: string;
      description: string;
      owasp_category: string | null;
      mitre_technique: string | null;
      detected_at: string;
    }>
  > {
    const result = await this.pool.query(
      `SELECT
         re.id,
         re.config_id,
         re.from_server_id,
         fs.name   AS from_server_name,
         fs.slug   AS from_server_slug,
         re.to_server_id,
         ts.name   AS to_server_name,
         ts.slug   AS to_server_slug,
         re.edge_type,
         re.pattern_id,
         re.severity,
         re.description,
         re.owasp_category,
         re.mitre_technique,
         re.detected_at
       FROM risk_edges re
       JOIN servers fs ON fs.id = re.from_server_id
       JOIN servers ts ON ts.id = re.to_server_id
       WHERE re.from_server_id = $1 OR re.to_server_id = $1
       ORDER BY
         CASE re.severity
           WHEN 'critical' THEN 0
           WHEN 'high'     THEN 1
           WHEN 'medium'   THEN 2
           WHEN 'low'      THEN 3
           ELSE 4
         END,
         re.detected_at DESC
       LIMIT 50`,
      [serverId]
    );
    return result.rows;
  }

  /**
   * Apply score caps recommended by the risk matrix to servers.latest_score.
   * Only lowers a score — never raises it.
   * caps is a map of server_id → cap value (e.g. { "uuid-123": 40 }).
   */
  async applyRiskScoreCaps(caps: Record<string, number>): Promise<number> {
    let applied = 0;
    for (const [serverId, cap] of Object.entries(caps)) {
      const result = await this.pool.query(
        `UPDATE servers SET latest_score = LEAST(latest_score, $1), updated_at = NOW()
         WHERE id = $2 AND latest_score > $1`,
        [cap, serverId]
      );
      if ((result.rowCount ?? 0) > 0) applied++;
    }
    return applied;
  }

  // ─── Dynamic Test Result Operations ──────────────────────────────────────

  /**
   * Persist one dynamic test session result.
   * Append-only (ADR-008) — never updated after insert.
   *
   * Called from the scanner pipeline (Stage 5b) after DynamicTester.test()
   * completes, regardless of whether the server consented or not.
   * Storing both outcomes lets us track coverage and consent ratios.
   */
  async saveDynamicReport(
    serverId: string,
    scanId: string | null,
    report: {
      endpoint: string;
      consented: boolean;
      consent_method: string | null;
      tested_at: string;
      elapsed_ms: number;
      tools_tested: number;
      tools_skipped: number;
      output_findings_count: number;
      injection_vulnerable_count: number;
      output_injection_risk: string;
      injection_vulnerability: string;
      schema_compliance: string;
      timing_anomalies: number;
      raw_report: Record<string, unknown>;
    }
  ): Promise<string> {
    const result = await this.pool.query(
      `INSERT INTO dynamic_test_results (
         server_id, scan_id, endpoint,
         consented, consent_method, tested_at, elapsed_ms,
         tools_tested, tools_skipped,
         output_findings_count, injection_vulnerable_count,
         output_injection_risk, injection_vulnerability,
         schema_compliance, timing_anomalies, raw_report
       ) VALUES (
         $1, $2, $3,
         $4, $5, $6, $7,
         $8, $9,
         $10, $11,
         $12, $13,
         $14, $15, $16
       ) RETURNING id`,
      [
        serverId,
        scanId,
        report.endpoint,
        report.consented,
        report.consent_method,
        new Date(report.tested_at),
        report.elapsed_ms,
        report.tools_tested,
        report.tools_skipped,
        report.output_findings_count,
        report.injection_vulnerable_count,
        report.output_injection_risk,
        report.injection_vulnerability,
        report.schema_compliance,
        report.timing_anomalies,
        JSON.stringify(report.raw_report),
      ]
    );
    return result.rows[0].id;
  }

  /**
   * Return all dynamic test results for a server, newest first.
   * Excludes raw_report (large JSONB) unless the caller explicitly needs it.
   * Used by the API to surface dynamic test history on server detail pages.
   */
  async getDynamicResultsForServer(
    serverId: string,
    limit: number = 20
  ): Promise<Array<{
    id: string;
    scan_id: string | null;
    endpoint: string;
    consented: boolean;
    consent_method: string | null;
    tested_at: Date;
    elapsed_ms: number;
    tools_tested: number;
    tools_skipped: number;
    output_findings_count: number;
    injection_vulnerable_count: number;
    output_injection_risk: string;
    injection_vulnerability: string;
    schema_compliance: string;
    timing_anomalies: number;
    created_at: Date;
  }>> {
    const result = await this.pool.query(
      `SELECT
         id, scan_id, endpoint,
         consented, consent_method, tested_at, elapsed_ms,
         tools_tested, tools_skipped,
         output_findings_count, injection_vulnerable_count,
         output_injection_risk, injection_vulnerability,
         schema_compliance, timing_anomalies, created_at
       FROM dynamic_test_results
       WHERE server_id = $1
       ORDER BY tested_at DESC
       LIMIT $2`,
      [serverId, limit]
    );
    return result.rows;
  }

  /**
   * Return the most recent dynamic test result for a server.
   * Used to quickly check if a server has been recently tested and
   * whether it passed consent + whether injection vulns were found.
   */
  async getLatestDynamicResultForServer(serverId: string): Promise<{
    id: string;
    consented: boolean;
    consent_method: string | null;
    tested_at: Date;
    tools_tested: number;
    output_findings_count: number;
    injection_vulnerable_count: number;
    output_injection_risk: string;
    injection_vulnerability: string;
    schema_compliance: string;
  } | null> {
    const result = await this.pool.query(
      `SELECT
         id, consented, consent_method, tested_at,
         tools_tested, output_findings_count, injection_vulnerable_count,
         output_injection_risk, injection_vulnerability, schema_compliance
       FROM dynamic_test_results
       WHERE server_id = $1
       ORDER BY tested_at DESC
       LIMIT 1`,
      [serverId]
    );
    return result.rows[0] ?? null;
  }

  // ─── Attack Chains ─────────────────────────────────────────────────────────

  /**
   * Get latest finding rule IDs for each server in a set.
   * Used by AttackGraphEngine to populate `server_findings` for scoring.
   * Returns only the most recent scan's findings per server.
   */
  async getFindingRuleIdsByServerIds(
    serverIds: string[]
  ): Promise<Record<string, string[]>> {
    if (serverIds.length === 0) return {};

    const result = await this.pool.query(
      `SELECT DISTINCT ON (f.server_id, f.rule_id)
              f.server_id, f.rule_id
       FROM findings f
       JOIN scans s ON f.scan_id = s.id
       WHERE f.server_id = ANY($1::uuid[])
         AND s.status = 'completed'
       ORDER BY f.server_id, f.rule_id, s.completed_at DESC`,
      [serverIds]
    );

    const map: Record<string, string[]> = {};
    for (const row of result.rows) {
      const existing = map[row.server_id] ?? [];
      existing.push(row.rule_id);
      map[row.server_id] = existing;
    }
    return map;
  }

  /**
   * Get attack chains involving a specific server (appears in any step).
   * Used by server detail page to show which kill chains this server participates in.
   */
  async getAttackChainsForServer(serverId: string): Promise<
    Array<{
      id: string;
      chain_id: string;
      config_id: string;
      kill_chain_id: string;
      kill_chain_name: string;
      steps: unknown[];
      exploitability_overall: number;
      exploitability_rating: string;
      narrative: string;
      mitigations: unknown[];
      owasp_refs: string[];
      mitre_refs: string[];
      created_at: Date;
    }>
  > {
    const result = await this.pool.query(
      `SELECT DISTINCT ON (ac.chain_id)
              ac.id, ac.chain_id, ac.config_id,
              ac.kill_chain_id, ac.kill_chain_name,
              ac.steps, ac.exploitability_overall, ac.exploitability_rating,
              ac.narrative, ac.mitigations, ac.owasp_refs, ac.mitre_refs,
              ac.created_at
       FROM attack_chains ac
       WHERE ac.steps::jsonb @> $1::jsonb
       ORDER BY ac.chain_id, ac.created_at DESC`,
      [JSON.stringify([{ server_id: serverId }])]
    );
    return result.rows;
  }

  /**
   * Insert attack chains (append-only, ADR-008).
   *
   * @param configId — hash of the server ID set
   * @param chains — array of attack chain records to persist
   */
  async insertAttackChains(
    configId: string,
    chains: Array<{
      chain_id: string;
      kill_chain_id: string;
      kill_chain_name: string;
      steps: unknown[];
      exploitability_overall: number;
      exploitability_rating: string;
      exploitability_factors: unknown[];
      narrative: string;
      mitigations: unknown[];
      owasp_refs: string[];
      mitre_refs: string[];
      evidence: unknown;
    }>
  ): Promise<void> {
    for (const chain of chains) {
      await this.pool.query(
        `INSERT INTO attack_chains
           (chain_id, config_id, kill_chain_id, kill_chain_name,
            steps, exploitability_overall, exploitability_rating,
            exploitability_factors, narrative, mitigations,
            owasp_refs, mitre_refs, evidence)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          chain.chain_id,
          configId,
          chain.kill_chain_id,
          chain.kill_chain_name,
          JSON.stringify(chain.steps),
          chain.exploitability_overall,
          chain.exploitability_rating,
          JSON.stringify(chain.exploitability_factors),
          chain.narrative,
          JSON.stringify(chain.mitigations),
          chain.owasp_refs,
          chain.mitre_refs,
          JSON.stringify(chain.evidence),
        ]
      );
    }
  }

  /**
   * Get attack chains for a config. Returns most recent analysis first.
   */
  async getAttackChainsForConfig(configId: string): Promise<
    Array<{
      id: string;
      chain_id: string;
      kill_chain_id: string;
      kill_chain_name: string;
      steps: unknown[];
      exploitability_overall: number;
      exploitability_rating: string;
      narrative: string;
      mitigations: unknown[];
      owasp_refs: string[];
      mitre_refs: string[];
      created_at: Date;
    }>
  > {
    const result = await this.pool.query(
      `SELECT id, chain_id, kill_chain_id, kill_chain_name,
              steps, exploitability_overall, exploitability_rating,
              narrative, mitigations, owasp_refs, mitre_refs, created_at
       FROM attack_chains
       WHERE config_id = $1
       ORDER BY created_at DESC`,
      [configId]
    );
    return result.rows;
  }

  /**
   * Get chain history for trend analysis.
   * Returns all occurrences of a specific chain_id over time.
   */
  async getChainHistory(chainId: string): Promise<
    Array<{
      exploitability_overall: number;
      exploitability_rating: string;
      created_at: Date;
    }>
  > {
    const result = await this.pool.query(
      `SELECT exploitability_overall, exploitability_rating, created_at
       FROM attack_chains
       WHERE chain_id = $1
       ORDER BY created_at ASC`,
      [chainId]
    );
    return result.rows;
  }

  // ─── Server Profile Operations ────────────────────────────────────────────

  /**
   * Insert a server profile for a scan. Uses ON CONFLICT to handle re-runs
   * of the same scan (uq_sp_server_scan unique constraint).
   * Append-only for new scans (ADR-008).
   */
  async insertServerProfile(input: {
    server_id: string;
    scan_id: string;
    profile_type: string;
    capabilities: unknown[];
    attack_surfaces: string[];
    data_flow_pairs: unknown[];
    threats: unknown[];
    summary: string;
    has_source_code: boolean;
    has_connection: boolean;
    has_dependencies: boolean;
    tool_count: number;
  }): Promise<void> {
    await this.pool.query(
      `INSERT INTO server_profiles (
        server_id, scan_id, profile_type, capabilities, attack_surfaces,
        data_flow_pairs, threats, summary, has_source_code, has_connection,
        has_dependencies, tool_count
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      ON CONFLICT (server_id, scan_id) DO UPDATE SET
        profile_type = EXCLUDED.profile_type,
        capabilities = EXCLUDED.capabilities,
        attack_surfaces = EXCLUDED.attack_surfaces,
        data_flow_pairs = EXCLUDED.data_flow_pairs,
        threats = EXCLUDED.threats,
        summary = EXCLUDED.summary,
        has_source_code = EXCLUDED.has_source_code,
        has_connection = EXCLUDED.has_connection,
        has_dependencies = EXCLUDED.has_dependencies,
        tool_count = EXCLUDED.tool_count`,
      [
        input.server_id,
        input.scan_id,
        input.profile_type,
        JSON.stringify(input.capabilities),
        input.attack_surfaces,
        JSON.stringify(input.data_flow_pairs),
        JSON.stringify(input.threats),
        input.summary,
        input.has_source_code,
        input.has_connection,
        input.has_dependencies,
        input.tool_count,
      ]
    );
  }

  /**
   * Get the latest profile for a server (most recent scan).
   * Returns null if no profile exists (server never scanned with Phase 1 pipeline).
   */
  async getLatestProfileForServer(serverId: string): Promise<{
    profile_type: string;
    capabilities: unknown[];
    attack_surfaces: string[];
    data_flow_pairs: unknown[];
    threats: unknown[];
    summary: string;
    has_source_code: boolean;
    has_connection: boolean;
    has_dependencies: boolean;
    tool_count: number;
    created_at: Date;
  } | null> {
    const result = await this.pool.query(
      `SELECT profile_type, capabilities, attack_surfaces, data_flow_pairs,
              threats, summary, has_source_code, has_connection, has_dependencies,
              tool_count, created_at
       FROM server_profiles
       WHERE server_id = $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [serverId]
    );
    return result.rows[0] ?? null;
  }

  /**
   * Get profile history for a server — used for capability drift detection
   * and trend analysis. Returns most recent profiles first.
   */
  async getProfileHistory(serverId: string, limit = 10): Promise<Array<{
    profile_type: string;
    capabilities: unknown[];
    attack_surfaces: string[];
    summary: string;
    tool_count: number;
    created_at: Date;
  }>> {
    const result = await this.pool.query(
      `SELECT profile_type, capabilities, attack_surfaces, summary, tool_count, created_at
       FROM server_profiles
       WHERE server_id = $1
       ORDER BY created_at DESC
       LIMIT $2`,
      [serverId, limit]
    );
    return result.rows;
  }

  /**
   * Return the enriched dependency rows previously persisted by
   * `upsertDependencies()`. Used by the compliance-agents package to assemble
   * an `AnalysisContext` from DB state without re-running the OSV audit —
   * compliance scans run after regular scans and reuse the already-audited
   * dependency snapshot.
   */
  async getDependenciesForServer(serverId: string): Promise<Array<{
    name: string;
    version: string | null;
    has_known_cve: boolean;
    cve_ids: string[];
    last_updated: Date | null;
  }>> {
    const result = await this.pool.query(
      `SELECT name, version, has_known_cve, cve_ids, last_updated
         FROM dependencies
         WHERE server_id = $1
         ORDER BY name`,
      [serverId]
    );
    return result.rows.map((r) => ({
      name: r.name as string,
      version: (r.version as string | null) ?? null,
      has_known_cve: Boolean(r.has_known_cve),
      cve_ids: (r.cve_ids as string[] | null) ?? [],
      last_updated: (r.last_updated as Date | null) ?? null,
    }));
  }

  // ─── Compliance Agents (ADR-009) ───────────────────────────────────────────
  //
  // Persistence for the adversarial compliance framework. Three tables back
  // this module (migrate.ts → 012_compliance_agents):
  //
  //   compliance_findings   — append-only, judge-confirmed rows only. The
  //                           orchestrator filters out non-confirmed verdicts
  //                           in orchestrator.ts before we ever reach this
  //                           layer, so a SELECT here is always safe to
  //                           surface publicly.
  //   compliance_agent_runs — append-only LLM audit trail. Required by ADR-009
  //                           for regulator-grade replayability. Every single
  //                           LLM call (synthesis + execution, cached or live)
  //                           must land here before the caller exits.
  //   compliance_test_cache — mutable by design: ON CONFLICT (cache_key) DO
  //                           UPDATE refreshes the content_hash so stale
  //                           bundles invalidate themselves automatically on
  //                           next scan. This is the ONE compliance table
  //                           where UPSERT is allowed (cache semantics, not
  //                           audit semantics).
  //
  // Every "latest scan" resolution uses the `compliance_findings` table
  // directly (not the generic `scans` table) because a server may have had
  // many `pnpm scan` passes without a compliance run — only compliance runs
  // produce compliance_findings rows.

  async insertComplianceFinding(
    record: Omit<ComplianceFindingRecord, "id" | "created_at">
  ): Promise<string> {
    const result = await this.pool.query(
      `INSERT INTO compliance_findings (
         scan_id, server_id, framework, rule_id, category_control,
         severity, confidence, bundle_id, test_id, test_hypothesis,
         judge_rationale, evidence_chain, remediation
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       RETURNING id`,
      [
        record.scan_id,
        record.server_id,
        record.framework,
        record.rule_id,
        record.category_control,
        record.severity,
        record.confidence,
        record.bundle_id,
        record.test_id,
        record.test_hypothesis,
        record.judge_rationale,
        JSON.stringify(record.evidence_chain),
        record.remediation,
      ]
    );
    return result.rows[0].id as string;
  }

  async insertComplianceAgentRun(
    record: Omit<ComplianceAgentRun, "id" | "created_at">
  ): Promise<string> {
    const result = await this.pool.query(
      `INSERT INTO compliance_agent_runs (
         scan_id, server_id, rule_id, framework, phase, cache_key,
         model, temperature, max_tokens, prompt, response,
         cached, duration_ms, input_tokens, output_tokens
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
       RETURNING id`,
      [
        record.scan_id,
        record.server_id,
        record.rule_id,
        record.framework,
        record.phase,
        record.cache_key,
        record.model,
        record.temperature,
        record.max_tokens,
        JSON.stringify(record.prompt),
        JSON.stringify(record.response),
        record.cached,
        record.duration_ms,
        record.input_tokens,
        record.output_tokens,
      ]
    );
    return result.rows[0].id as string;
  }

  async upsertComplianceTestCache(
    record: Omit<ComplianceTestCache, "id" | "created_at">
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO compliance_test_cache (
         cache_key, server_id, rule_id, framework, bundle_id,
         content_hash, tests, model
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (cache_key) DO UPDATE SET
         content_hash = EXCLUDED.content_hash,
         tests = EXCLUDED.tests,
         bundle_id = EXCLUDED.bundle_id,
         model = EXCLUDED.model,
         created_at = NOW()`,
      [
        record.cache_key,
        record.server_id,
        record.rule_id,
        record.framework,
        record.bundle_id,
        record.content_hash,
        JSON.stringify(record.tests),
        record.model,
      ]
    );
  }

  /**
   * Freshness-gated cache lookup. Returns the cached entry ONLY when the
   * stored `content_hash` matches the caller's expected hash, so a drift
   * in the underlying EvidenceBundle silently invalidates the cache and
   * forces a re-synthesis. Never returns a stale entry.
   */
  async getComplianceTestCacheByKey(
    cacheKey: string,
    expectedContentHash: string
  ): Promise<ComplianceTestCache | null> {
    const result = await this.pool.query(
      `SELECT id, cache_key, server_id, rule_id, framework, bundle_id,
              content_hash, tests, model, created_at
         FROM compliance_test_cache
         WHERE cache_key = $1 AND content_hash = $2
         LIMIT 1`,
      [cacheKey, expectedContentHash]
    );
    const row = result.rows[0];
    if (!row) return null;
    return row as ComplianceTestCache;
  }

  /**
   * Resolve the latest compliance scan for a server. Returns null if the
   * server has never been run through the compliance pipeline.
   */
  async getLatestComplianceScanId(serverId: string): Promise<string | null> {
    const result = await this.pool.query(
      `SELECT scan_id
         FROM compliance_findings
         WHERE server_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
      [serverId]
    );
    return (result.rows[0]?.scan_id as string | undefined) ?? null;
  }

  /**
   * Judge-confirmed compliance findings from the latest compliance scan for
   * a server. Optional framework filter. Ordered by framework (regulator
   * priority: EU AI Act first → MITRE ATLAS → OWASP MCP → OWASP ASI → CoSAI
   * → MAESTRO) then severity (critical → informational).
   */
  async getComplianceFindingsForServer(
    serverId: string,
    framework?: ComplianceFrameworkId
  ): Promise<ComplianceFindingRecord[]> {
    const params: unknown[] = [serverId];
    let frameworkClause = "";
    if (framework) {
      params.push(framework);
      frameworkClause = ` AND framework = $2`;
    }
    const result = await this.pool.query(
      `SELECT id, scan_id, server_id, framework, rule_id, category_control,
              severity, confidence, bundle_id, test_id, test_hypothesis,
              judge_rationale, evidence_chain, remediation, created_at
         FROM compliance_findings
         WHERE server_id = $1
           AND scan_id = (
             SELECT scan_id FROM compliance_findings
               WHERE server_id = $1
               ORDER BY created_at DESC
               LIMIT 1
           )
           ${frameworkClause}
         ORDER BY
           CASE framework
             WHEN 'eu_ai_act'   THEN 1
             WHEN 'mitre_atlas' THEN 2
             WHEN 'owasp_mcp'   THEN 3
             WHEN 'owasp_asi'   THEN 4
             WHEN 'cosai'       THEN 5
             WHEN 'maestro'     THEN 6
             ELSE 7
           END,
           CASE severity
             WHEN 'critical'      THEN 1
             WHEN 'high'          THEN 2
             WHEN 'medium'        THEN 3
             WHEN 'low'           THEN 4
             WHEN 'informational' THEN 5
             ELSE 6
           END,
           rule_id`,
      params
    );
    return result.rows as ComplianceFindingRecord[];
  }

  /**
   * Ecosystem-wide compliance posture. Aggregates the latest compliance scan
   * per server and groups findings by framework. Used by the future
   * regulator-facing `/api/v1/ecosystem/compliance/stats` endpoint.
   *
   * Caveat: this reports observed findings only. "Clean" servers (zero
   * findings for a framework) cannot be attributed without a separate
   * compliance_scans table — deferred to a follow-up. Totals below
   * therefore describe violation density, not compliance coverage.
   */
  async getEcosystemComplianceStats(): Promise<{
    by_framework: Array<{
      framework: ComplianceFrameworkId;
      servers_with_findings: number;
      total_findings: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
      informational: number;
    }>;
    total_servers_scanned: number;
    last_scan_at: Date | null;
  }> {
    const frameworkRows = await this.pool.query(
      `WITH latest_per_server AS (
         SELECT DISTINCT ON (server_id)
           server_id, scan_id, created_at
         FROM compliance_findings
         ORDER BY server_id, created_at DESC
       )
       SELECT cf.framework,
              COUNT(DISTINCT cf.server_id)                                       AS servers_with_findings,
              COUNT(*)                                                           AS total_findings,
              SUM(CASE WHEN cf.severity = 'critical'      THEN 1 ELSE 0 END)     AS critical,
              SUM(CASE WHEN cf.severity = 'high'          THEN 1 ELSE 0 END)     AS high,
              SUM(CASE WHEN cf.severity = 'medium'        THEN 1 ELSE 0 END)     AS medium,
              SUM(CASE WHEN cf.severity = 'low'           THEN 1 ELSE 0 END)     AS low,
              SUM(CASE WHEN cf.severity = 'informational' THEN 1 ELSE 0 END)     AS informational
         FROM compliance_findings cf
         JOIN latest_per_server lps
           ON cf.server_id = lps.server_id AND cf.scan_id = lps.scan_id
         GROUP BY cf.framework
         ORDER BY cf.framework`
    );
    const totals = await this.pool.query(
      `SELECT COUNT(DISTINCT server_id) AS cnt, MAX(created_at) AS last_at
         FROM compliance_findings`
    );
    return {
      by_framework: frameworkRows.rows.map((r) => ({
        framework: r.framework as ComplianceFrameworkId,
        servers_with_findings: parseInt(r.servers_with_findings, 10) || 0,
        total_findings: parseInt(r.total_findings, 10) || 0,
        critical: parseInt(r.critical, 10) || 0,
        high: parseInt(r.high, 10) || 0,
        medium: parseInt(r.medium, 10) || 0,
        low: parseInt(r.low, 10) || 0,
        informational: parseInt(r.informational, 10) || 0,
      })),
      total_servers_scanned: parseInt(totals.rows[0]?.cnt ?? "0", 10) || 0,
      last_scan_at: (totals.rows[0]?.last_at as Date | null) ?? null,
    };
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private slugify(name: string): string {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .substring(0, 500);
  }

  /**
   * Extract github_stars from raw_metadata.
   * Different crawlers use different keys: "stars", "github_stars", "stargazers_count".
   */
  private _extractGithubStars(raw: Record<string, unknown>): number | null {
    const val = raw.stars ?? raw.github_stars ?? raw.stargazers_count;
    if (typeof val === "number" && Number.isFinite(val) && val >= 0) return val;
    return null;
  }
}
