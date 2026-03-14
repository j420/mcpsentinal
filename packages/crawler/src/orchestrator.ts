import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlStats, CrawlPersistStats } from "./types.js";
import type { DiscoveredServer, DatabaseQueries } from "@mcp-sentinel/database";
import { NpmCrawler } from "./sources/npm.js";
import { GitHubCrawler } from "./sources/github.js";
import { PyPICrawler } from "./sources/pypi.js";
import { PulseMCPCrawler } from "./sources/pulsemcp.js";
import { SmitheryCrawler } from "./sources/smithery.js";
import { McpRegistryCrawler } from "./sources/mcpregistry.js";
import { ModelcontextprotocolRepoCrawler } from "./sources/modelcontextprotocol-repo.js";

const logger = pino({ name: "crawler:orchestrator" });

export class CrawlOrchestrator {
  private sources: CrawlerSource[];

  constructor(sourceNames?: string[], injectSources?: CrawlerSource[]) {
    if (injectSources) {
      this.sources = injectSources;
      return;
    }

    const allSources: CrawlerSource[] = [
      // Official sources run first — highest trust signal, seeds dedup keys
      new McpRegistryCrawler(),
      new ModelcontextprotocolRepoCrawler(),
      // Community registries
      new PulseMCPCrawler(),
      new SmitheryCrawler(),
      // Package registries
      new NpmCrawler(),
      new PyPICrawler(),
      // Broad GitHub search — widest net, highest duplicates
      new GitHubCrawler(),
    ];

    if (sourceNames && sourceNames.length > 0) {
      this.sources = allSources.filter((s) =>
        sourceNames.includes(s.name)
      );
    } else {
      this.sources = allSources;
    }
  }

  async crawlAll(): Promise<CrawlStats> {
    const { results, uniqueServers } = await this._runCrawlers();
    return this._buildStats(results, uniqueServers);
  }


  async crawlAndPersist(db: DatabaseQueries): Promise<CrawlPersistStats> {
    const runStart = new Date();
    const { results, uniqueServers, allServers } = await this._runCrawlers();

    let persisted = 0;
    let persist_errors = 0;
    let new_to_db = 0;
    let enriched_existing = 0;

    logger.info(
      { total: allServers.length, unique: uniqueServers.size },
      "Persisting discovered servers — canonical dedup: github_url → npm → pypi → slug"
    );

    for (const server of allServers) {
      try {
        const { is_new } = await db.upsertServerDedup(server);
        persisted++;
        if (is_new) new_to_db++;
        else enriched_existing++;

        if (persisted % 100 === 0) {
          logger.info(
            { persisted, total: allServers.length, new_to_db, enriched_existing },
            "Persist progress"
          );
        }
      } catch (err) {
        persist_errors++;
        logger.error({ server: server.name, err }, "Failed to persist server");
      }
    }

    const stats = this._buildStats(results, uniqueServers);
    const completedAt = new Date();
    const elapsed_ms = completedAt.getTime() - runStart.getTime();

    // Persist crawl run record for historical yield tracking (non-fatal if it fails)
    try {
      await db.insertCrawlRun({
        started_at: runStart,
        completed_at: completedAt,
        total_discovered: stats.total_discovered,
        new_to_db,
        enriched_existing,
        persist_errors,
        per_source: stats.per_source,
        data_quality: stats.data_quality,
        elapsed_ms,
      });
    } catch (err) {
      logger.warn({ err }, "Failed to persist crawl run stats — non-fatal");
    }

    logger.info(
      {
        persisted,
        persist_errors,
        new_to_db,
        enriched_existing,
        in_memory_unique: stats.new_unique,
        elapsed_ms,
      },
      "Crawl+persist run complete"
    );

    return { ...stats, new_to_db, enriched_existing, persisted, persist_errors };
  }

  getResults(): CrawlerSource[] {
    return this.sources;
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  private async _runCrawlers(): Promise<{
    results: CrawlResult[];
    uniqueServers: Map<string, DiscoveredServer>;
    allServers: DiscoveredServer[];
  }> {
    const results: CrawlResult[] = [];
    const uniqueServers = new Map<string, DiscoveredServer>();
    const allServers: DiscoveredServer[] = [];

    logger.info(
      { sources: this.sources.map((s) => s.name) },
      "Starting crawl run"
    );

    for (const source of this.sources) {
      logger.info({ source: source.name }, "Crawling source");

      try {
        const result = await source.crawl();
        results.push(result);

        let newUnique = 0;
        for (const server of result.servers) {
          allServers.push(server);
          const key = this._deduplicationKey(server);
          if (!uniqueServers.has(key)) {
            uniqueServers.set(key, server);
            newUnique++;
          }
        }
        result.new_unique = newUnique;
        result.duplicates = result.servers_found - newUnique;

        logger.info(
          {
            source: source.name,
            found: result.servers_found,
            unique: result.new_unique,
            duplicates: result.duplicates,
            errors: result.errors,
            elapsed_ms: result.elapsed_ms,
          },
          "Source crawl complete"
        );
      } catch (err) {
        logger.error({ source: source.name, err }, "Source crawl failed");
        results.push({
          source: source.name,
          servers_found: 0,
          new_unique: 0,
          duplicates: 0,
          errors: 1,
          elapsed_ms: 0,
          servers: [],
        });
      }
    }

    return { results, uniqueServers, allServers };
  }

  private _buildStats(
    results: CrawlResult[],
    uniqueServers: Map<string, DiscoveredServer>
  ): CrawlStats {
    const allDiscovered = results.flatMap((r) => r.servers);

    const stats: CrawlStats = {
      total_discovered: allDiscovered.length,
      new_unique: uniqueServers.size,
      per_source: results.map((r) => ({
        source: r.source,
        found: r.servers_found,
        unique: r.new_unique,
        duplicates: r.duplicates,
        errors: r.errors,
        elapsed_ms: r.elapsed_ms,
      })),
      data_quality: {
        with_github_url: allDiscovered.filter((s) => s.github_url).length,
        with_npm_package: allDiscovered.filter((s) => s.npm_package).length,
        with_description: allDiscovered.filter((s) => s.description).length,
        with_category: allDiscovered.filter((s) => s.category).length,
      },
    };

    logger.info(
      {
        total: stats.total_discovered,
        unique: stats.new_unique,
        quality: stats.data_quality,
      },
      "Crawl run complete"
    );

    return stats;
  }

  /**
   * Deduplication key: normalized GitHub URL > npm package > pypi package > name+author
   */
  private _deduplicationKey(server: {
    github_url?: string | null;
    npm_package?: string | null;
    pypi_package?: string | null;
    name: string;
    author?: string | null;
  }): string {
    if (server.github_url) {
      return `gh:${server.github_url.toLowerCase().replace(/\.git$/, "").replace(/\/$/, "")}`;
    }
    if (server.npm_package) {
      return `npm:${server.npm_package.toLowerCase()}`;
    }
    if (server.pypi_package) {
      return `pypi:${server.pypi_package.toLowerCase()}`;
    }
    return `name:${server.name.toLowerCase()}:${(server.author || "unknown").toLowerCase()}`;
  }
}
