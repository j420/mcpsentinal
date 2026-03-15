/**
 * P9 — Scanner Engine Engineer
 * ScanPipeline — the core MCP Sentinel scan orchestrator.
 *
 * Chains the full security intelligence pipeline for each server:
 *
 *   [DB Queue]
 *       ↓
 *   Stage 0: createScan()          — open an immutable scan record
 *       ↓
 *   Stage 1: SourceFetcher         — download source code from GitHub
 *       ↓
 *   Stage 2: DependencyAuditor     — enrich deps with CVE data via OSV API
 *       ↓
 *   Stage 3: discoverEndpoint()    — find live HTTP endpoint from sources metadata
 *       ↓
 *   Stage 4: MCPConnector          — enumerate tools via initialize + tools/list
 *       ↓
 *   Stage 5: AnalysisEngine        — run all 83 detection rules → FindingInput[]
 *       ↓
 *   Stage 6: computeScore()        — compute composite 0–100 score
 *       ↓
 *   Stage 7: Persist               — insertFindings + insertScore + completeScan
 *
 * Key properties:
 * - Concurrency-limited: configurable number of parallel server scans (default: 5)
 * - Stage isolation: a failed stage does not abort downstream stages
 *   (e.g., failed source fetch → analysis still runs on tool descriptions)
 * - Structured logging: every stage logs with a correlation ID (server_id prefix)
 * - SAFETY: MCPConnector ONLY calls initialize + tools/list, never invokes tools
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";
import type { DatabaseQueries, Server } from "@mcp-sentinel/database";
import { AnalysisEngine, loadRules, getRulesVersion } from "@mcp-sentinel/analyzer";
import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import { MCPConnector } from "@mcp-sentinel/connector";
import { computeScore } from "@mcp-sentinel/scorer";
import { SourceFetcher } from "./fetcher.js";
import { DependencyAuditor } from "./auditor.js";
import type { ScanOptions, ScanServerResult, ScanRunStats, EnrichedDependency } from "./types.js";

const logger = pino({ name: "scanner:pipeline" });

const DEFAULT_CONCURRENCY = 5;
const DEFAULT_LIMIT = 100;
const DEFAULT_STALE_DAYS = 7;

// Resolve rules directory relative to the monorepo root.
// __dirname is packages/scanner/src/  → ../../../../rules resolves to <root>/rules
const __dirname = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_RULES_DIR = path.resolve(__dirname, "../../../rules");

export interface PipelineConfig {
  /** Override the rules directory path (default: <monorepo-root>/rules) */
  rulesDir?: string;
}

export class ScanPipeline {
  private readonly fetcher: SourceFetcher;
  private readonly auditor: DependencyAuditor;
  private readonly connector: MCPConnector;
  private readonly rulesDir: string;

  constructor(
    private readonly db: DatabaseQueries,
    config?: PipelineConfig
  ) {
    this.fetcher = new SourceFetcher();
    this.auditor = new DependencyAuditor();
    this.connector = new MCPConnector();
    this.rulesDir = config?.rulesDir ?? DEFAULT_RULES_DIR;
  }

  /**
   * Run the scan pipeline.
   *
   * In single-server mode (options.serverId), scans exactly that server.
   * In batch mode, selects from the queue of unscanned (or stale) servers.
   */
  async run(options: ScanOptions = {}): Promise<ScanRunStats> {
    const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
    const limit = options.limit ?? DEFAULT_LIMIT;
    const staleDays = options.staleDays ?? DEFAULT_STALE_DAYS;
    const runStart = Date.now();

    // ── Load rules once — shared across all scans in this run ────────────────
    const rules = loadRules(this.rulesDir);
    if (rules.length === 0) {
      throw new Error(
        `No detection rules found in ${this.rulesDir}. ` +
          "Ensure the rules directory exists and contains .yaml files."
      );
    }

    const rulesVersion = getRulesVersion(rules);
    const ruleCategories: Record<string, string> = {};
    for (const rule of rules) {
      ruleCategories[rule.id] = rule.category;
    }
    const engine = new AnalysisEngine(rules);

    logger.info(
      { rules: rules.length, version: rulesVersion, concurrency, limit },
      "Scan pipeline starting"
    );

    // ── Select servers to scan ───────────────────────────────────────────────
    let servers: Server[];

    if (options.serverId) {
      const server = await this.db.getServerById(options.serverId);
      if (!server) {
        throw new Error(`Server not found: ${options.serverId}`);
      }
      servers = [server];
    } else {
      const mode = options.mode ?? (options.rescan ? "full" : "incremental");
      if (mode === "rescan-failed") {
        servers = await this.db.getFailedServers(limit);
      } else if (mode === "full") {
        // Full mode rescans every server regardless of when it was last scanned.
        // getServersNeedingRescan would miss servers scanned within staleDays.
        servers = await this.db.getAllServers(limit);
      } else if (options.rescan) {
        servers = await this.db.getServersNeedingRescan(staleDays, limit);
      } else {
        servers = await this.db.getUnscannedServers(limit);
      }
    }

    logger.info({ count: servers.length }, "Servers selected for scan queue");

    // ── Dry run: report what would be scanned ─────────────────────────────────
    if (options.dryRun) {
      const dryResults: ScanServerResult[] = servers.map((s) => ({
        server_id: s.id,
        server_name: s.name,
        success: false,
        findings_count: 0,
        score: null,
        error: "dry-run",
        elapsed_ms: 0,
        stages: {
          source_fetched: false,
          connection_attempted: false,
          connection_succeeded: false,
          dependencies_audited: false,
        },
      }));

      logger.info({ count: servers.length }, "Dry run complete — no servers scanned");

      return {
        total: servers.length,
        succeeded: 0,
        failed: 0,
        elapsed_ms: Date.now() - runStart,
        findings_total: 0,
        per_server: dryResults,
      };
    }

    // ── Concurrent scan execution with semaphore ──────────────────────────────
    const semaphore = new Semaphore(concurrency);

    const results: ScanServerResult[] = await Promise.all(
      servers.map((server) =>
        semaphore.run(() =>
          this.scanOneServer(server, engine, ruleCategories, rulesVersion)
        )
      )
    );

    const stats: ScanRunStats = {
      total: results.length,
      succeeded: results.filter((r) => r.success).length,
      failed: results.filter((r) => !r.success).length,
      elapsed_ms: Date.now() - runStart,
      findings_total: results.reduce((sum, r) => sum + r.findings_count, 0),
      per_server: results,
    };

    logger.info(
      {
        total: stats.total,
        succeeded: stats.succeeded,
        failed: stats.failed,
        findings: stats.findings_total,
        elapsed_s: (stats.elapsed_ms / 1000).toFixed(1),
        rules_version: rulesVersion,
      },
      "Scan pipeline complete"
    );

    return stats;
  }

  // ─── Single-Server Scan ────────────────────────────────────────────────────

  private async scanOneServer(
    server: Server,
    engine: AnalysisEngine,
    ruleCategories: Record<string, string>,
    rulesVersion: string
  ): Promise<ScanServerResult> {
    const serverStart = Date.now();
    const stages = {
      source_fetched: false,
      connection_attempted: false,
      connection_succeeded: false,
      dependencies_audited: false,
    };

    // Scoped child logger with correlation ID for this server
    const cid = server.id.substring(0, 8);
    const log = logger.child({ server: server.name, server_id: server.id, cid });
    log.info("Starting server scan");

    let scanId: string | null = null;

    try {
      // ── Stage 0: Open scan record ──────────────────────────────────────────
      scanId = await this.db.createScan(server.id, rulesVersion);

      // ── Stage 1: Fetch source code from GitHub ─────────────────────────────
      let sourceCode: string | null = null;
      let enrichedDeps: EnrichedDependency[] = [];
      let protocolResources: Array<{ uri: string; name: string; description?: string | null; mimeType?: string | null }> = [];
      let protocolPrompts: Array<{ name: string; description?: string | null; arguments?: Array<{ name: string; description?: string | null; required?: boolean }> }> = [];
      let protocolRoots: Array<{ uri: string; name?: string | null }> = [];
      let protocolCapabilities: AnalysisContext["declared_capabilities"] = null;

      if (server.github_url) {
        log.info({ github_url: server.github_url }, "Stage 1: Fetching source code");

        const fetched = await this.fetcher.fetchFromGitHub(server.github_url);

        if (fetched.source_code) {
          sourceCode = fetched.source_code;
          stages.source_fetched = true;
          log.info(
            { files: fetched.files_fetched.length, bytes: fetched.source_code.length },
            "Stage 1: Source code fetched"
          );
        } else {
          log.warn(
            { error: fetched.error },
            "Stage 1: Source fetch failed — continuing without source code"
          );
        }

        // ── Stage 2: Audit dependencies ────────────────────────────────────
        if (fetched.raw_dependencies.length > 0) {
          log.info(
            { deps: fetched.raw_dependencies.length },
            "Stage 2: Auditing dependencies via OSV"
          );

          enrichedDeps = await this.auditor.audit(fetched.raw_dependencies);
          stages.dependencies_audited = true;

          // Persist enriched dependencies to DB for historical tracking
          await this.db.upsertDependencies(server.id, enrichedDeps);

          const vulnCount = enrichedDeps.filter((d) => d.has_known_cve).length;
          log.info(
            { total_deps: enrichedDeps.length, with_cves: vulnCount },
            "Stage 2: Dependencies audited and persisted"
          );
        } else {
          log.info("Stage 2: No dependencies found — skipping audit");
        }
      } else {
        log.info("Stage 1+2: No GitHub URL — skipping source fetch and dependency audit");
      }

      // ── Stage 3+4: Discover endpoint and attempt live connection ───────────
      let connectionMetadata: AnalysisContext["connection_metadata"] = null;
      let liveTools: AnalysisContext["tools"] = [];
      let initMetadata: AnalysisContext["initialize_metadata"] = undefined;

      const endpoint = await this.discoverEndpoint(server);

      if (endpoint) {
        stages.connection_attempted = true;
        log.info({ endpoint }, "Stage 3+4: Attempting live MCP connection");

        const enumeration = await this.connector.enumerate(server.id, endpoint);

        if (enumeration.connection_success) {
          stages.connection_succeeded = true;
          liveTools = enumeration.tools;

          // Persist enumerated tools to DB
          await this.db.upsertTools(server.id, liveTools);

          connectionMetadata = {
            auth_required: false,
            transport: this.detectTransport(endpoint),
            response_time_ms: enumeration.response_time_ms,
          };

          // Capture initialize response fields for H2 rule (Initialize Response Injection).
          // serverInfo.version and instructions are the two fields H2 scans beyond server.name.
          // server.name is already in context.server.name; the analyzer combines all three.
          initMetadata = {
            server_version: enumeration.server_version ?? null,
            server_instructions: enumeration.server_instructions ?? null,
          };

          // Capture protocol surface data for Category I rules
          protocolResources = enumeration.resources ?? [];
          protocolPrompts = enumeration.prompts ?? [];
          protocolRoots = enumeration.roots ?? [];
          protocolCapabilities = enumeration.declared_capabilities ?? null;

          // Persist connection data: endpoint cache, health status, H2 rule data
          await this.db.updateServerConnectionData(server.id, {
            endpoint_url: endpoint,
            connection_status: "success",
            server_version: enumeration.server_version ?? null,
            server_instructions: enumeration.server_instructions ?? null,
          });

          log.info(
            {
              tools: liveTools.length,
              response_time_ms: enumeration.response_time_ms,
              server_version: enumeration.server_version ?? null,
              has_instructions: !!enumeration.server_instructions,
            },
            "Stage 3+4: Live connection succeeded — tools enumerated"
          );
        } else {
          // Connection attempted but failed — still record metadata for E1/E2 rules
          connectionMetadata = {
            auth_required: this.isAuthError(enumeration.connection_error),
            transport: this.detectTransport(endpoint),
            response_time_ms: enumeration.response_time_ms,
          };

          const isTimeout = (enumeration.connection_error ?? "").toLowerCase().includes("timeout");
          await this.db.updateServerConnectionData(server.id, {
            endpoint_url: endpoint,
            connection_status: isTimeout ? "timeout" : "failed",
          });

          log.warn(
            { error: enumeration.connection_error },
            "Stage 3+4: Live connection failed — proceeding with static analysis"
          );
        }
      } else {
        // No endpoint found — record status so UI shows "no endpoint" rather than unknown
        await this.db.updateServerConnectionData(server.id, {
          connection_status: "no_endpoint",
        });
        log.info("Stage 3+4: No endpoint discovered — static analysis only");
      }

      // ── Stage 4b: Fall back to stored tools when no live connection ────────
      // Enables full rule coverage (B, F, G rules) on servers with pre-seeded
      // or previously enumerated tools even when the live endpoint is offline.
      let toolsForAnalysis = liveTools;
      if (liveTools.length === 0) {
        const storedTools = await this.db.getToolsForServer(server.id);
        if (storedTools.length > 0) {
          toolsForAnalysis = storedTools.map((t) => ({
            name: t.name,
            description: t.description ?? "",
            input_schema: t.input_schema ?? {},
            annotations: null, // Stored tools don't have annotation data
          }));
          log.info(
            { stored_tools: storedTools.length },
            "Stage 4b: Using stored tools for static analysis"
          );
        }
      }

      // ── Stage 5: Assemble analysis context ────────────────────────────────
      const context: AnalysisContext = {
        server: {
          id: server.id,
          name: server.name,
          description: server.description,
          github_url: server.github_url,
        },
        tools: toolsForAnalysis,
        source_code: sourceCode,
        dependencies: enrichedDeps.map((d) => ({
          name: d.name,
          version: d.version,
          has_known_cve: d.has_known_cve,
          cve_ids: d.cve_ids,
          last_updated: d.last_updated,
        })),
        connection_metadata: connectionMetadata,
        initialize_metadata: initMetadata,
        // Category I: Protocol surface data
        resources: protocolResources ?? [],
        prompts: protocolPrompts ?? [],
        roots: protocolRoots ?? [],
        declared_capabilities: protocolCapabilities ?? null,
      };

      // ── Stage 5: Run all detection rules ──────────────────────────────────
      log.info({ rules: "all", tools: toolsForAnalysis.length }, "Stage 5: Running analysis engine");
      const findings = engine.analyze(context);
      log.info({ findings: findings.length }, "Stage 5: Analysis complete");

      // ── Stage 6: Compute composite score ──────────────────────────────────
      const score = computeScore(findings, ruleCategories);
      const hasLethalTrifecta = findings.some((f) => f.rule_id === "F1");
      log.info(
        {
          total_score: score.total_score,
          findings: findings.length,
          lethal_trifecta: hasLethalTrifecta,
          code_score: score.code_score,
          deps_score: score.deps_score,
          config_score: score.config_score,
        },
        "Stage 6: Score computed"
      );

      // ── Stage 7: Persist findings, score, close scan ──────────────────────
      if (findings.length > 0) {
        await this.db.insertFindings(server.id, scanId, findings);
      }

      await this.db.insertScore({
        server_id: server.id,
        scan_id: scanId,
        total_score: score.total_score,
        code_score: score.code_score,
        deps_score: score.deps_score,
        config_score: score.config_score,
        description_score: score.description_score,
        behavior_score: score.behavior_score,
        owasp_coverage: score.owasp_coverage,
        rules_version: rulesVersion,
      });

      await this.db.completeScan(scanId, findings.length, null, stages);

      const elapsed = Date.now() - serverStart;
      log.info(
        { elapsed_ms: elapsed, score: score.total_score, findings: findings.length },
        "Server scan complete"
      );

      return {
        server_id: server.id,
        server_name: server.name,
        success: true,
        findings_count: findings.length,
        score: score.total_score,
        error: null,
        elapsed_ms: elapsed,
        stages,
      };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      const elapsed = Date.now() - serverStart;
      log.error({ error, elapsed_ms: elapsed }, "Server scan failed");

      // Mark the scan record as failed so it's visible in the DB
      if (scanId) {
        try {
          await this.db.completeScan(scanId, 0, error.substring(0, 4000), stages);
        } catch (persistErr) {
          log.error({ persistErr }, "Failed to mark scan as failed in DB");
        }
      }

      return {
        server_id: server.id,
        server_name: server.name,
        success: false,
        findings_count: 0,
        score: null,
        error,
        elapsed_ms: elapsed,
        stages,
      };
    }
  }

  // ─── Endpoint Discovery ────────────────────────────────────────────────────

  /**
   * Attempt to discover a live HTTP endpoint for a server by inspecting
   * its source metadata. Checks raw_metadata from all discovery sources
   * for known endpoint field names.
   *
   * Registries known to include endpoint information:
   * - PulseMCP: endpoint, server_url, url
   * - Smithery: endpoint, qualifiedName (used to construct endpoint)
   * - Glama: endpoint, url
   * - McpRegistry: endpoint, url
   *
   * Returns null if no valid HTTP(S) endpoint can be found — this is normal
   * for GitHub/npm/PyPI-sourced servers which are local STDIO servers.
   */
  private async discoverEndpoint(server: Server): Promise<string | null> {
    try {
      const sources = await this.db.getServerSources(server.id);

      for (const source of sources) {
        const meta = source.raw_metadata as Record<string, unknown>;

        // Check common endpoint field names
        for (const field of [
          "endpoint",
          "server_url",
          "url",
          "endpoint_url",
          "baseUrl",
          "base_url",
          "serverUrl",
        ]) {
          const value = meta[field];
          if (typeof value === "string" && this.isHttpUrl(value)) {
            return value;
          }
        }

        // Smithery: qualifiedName → construct official Smithery endpoint
        if (
          source.source_name === "smithery" &&
          typeof meta.qualifiedName === "string" &&
          meta.qualifiedName.trim()
        ) {
          return `https://server.smithery.ai/${meta.qualifiedName}/mcp`;
        }
      }
    } catch (err) {
      logger.warn({ server_id: server.id, err }, "Endpoint discovery error — skipping live connection");
    }

    return null;
  }

  private isHttpUrl(url: string): boolean {
    try {
      const u = new URL(url);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  private detectTransport(endpoint: string): string {
    if (endpoint.endsWith("/sse") || endpoint.includes("?sse=") || endpoint.includes("&sse=")) {
      return "sse";
    }
    return "streamable-http";
  }

  /**
   * Heuristic to detect if a connection error was auth-related.
   * Used to populate connection_metadata.auth_required for E1 rule.
   */
  private isAuthError(error: string | null): boolean {
    if (!error) return false;
    const lower = error.toLowerCase();
    return (
      lower.includes("401") ||
      lower.includes("403") ||
      lower.includes("unauthorized") ||
      lower.includes("forbidden") ||
      lower.includes("authentication required") ||
      lower.includes("auth")
    );
  }
}

// ─── Semaphore ────────────────────────────────────────────────────────────────

/**
 * Simple semaphore for limiting the number of concurrent async operations.
 * Ensures we don't overwhelm the database, GitHub API, or OSV API with
 * too many parallel server scans.
 */
class Semaphore {
  private available: number;
  private readonly queue: Array<() => void> = [];

  constructor(private readonly maxConcurrent: number) {
    this.available = maxConcurrent;
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.available > 0) {
      this.available--;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => this.queue.push(resolve));
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) {
      // Hand the slot directly to the next waiter (don't increment + decrement)
      next();
    } else {
      this.available++;
    }
  }
}
