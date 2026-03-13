import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlStats } from "./types.js";
import type { DiscoveredServer, DatabaseQueries } from "@mcp-sentinel/database";
import { NpmCrawler } from "./sources/npm.js";
import { GitHubCrawler } from "./sources/github.js";
import { PyPICrawler } from "./sources/pypi.js";
import { PulseMCPCrawler } from "./sources/pulsemcp.js";
import { SmitheryCrawler } from "./sources/smithery.js";

const logger = pino({ name: "crawler:orchestrator" });

export class CrawlOrchestrator {
  private sources: CrawlerSource[];

  constructor(sourceNames?: string[], injectSources?: CrawlerSource[]) {
    if (injectSources) {
      this.sources = injectSources;
      return;
    }

    const allSources: CrawlerSource[] = [
      new PulseMCPCrawler(),
      new SmitheryCrawler(),
      new NpmCrawler(),
      new PyPICrawler(),
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

  async crawlAndPersist(
    db: DatabaseQueries
  ): Promise<CrawlStats & { persisted: number; persist_errors: number }> {
    const { results, uniqueServers } = await this._runCrawlers();

    const serverList = Array.from(uniqueServers.values());
    let persisted = 0;
    let persist_errors = 0;

    logger.info(
      { total: serverList.length },
      "Persisting unique servers to database"
    );

    for (const server of serverList) {
      try {
        await db.upsertServer(server);
        persisted++;
        if (persisted % 100 === 0) {
          logger.info(
            { persisted, total: serverList.length },
            "Persist progress"
          );
        }
      } catch (err) {
        persist_errors++;
        logger.error({ server: server.name, err }, "Failed to persist server");
      }
    }

    const stats = this._buildStats(results, uniqueServers);

    logger.info(
      { persisted, persist_errors, unique: stats.new_unique },
      "Crawl+persist run complete"
    );

    return { ...stats, persisted, persist_errors };
  }

  getResults(): CrawlerSource[] {
    return this.sources;
  }

  // ─── Private helpers ────────────────────────────────────────────────────────

  private async _runCrawlers(): Promise<{
    results: CrawlResult[];
    uniqueServers: Map<string, DiscoveredServer>;
  }> {
    const results: CrawlResult[] = [];
    const uniqueServers = new Map<string, DiscoveredServer>();

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

    return { results, uniqueServers };
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
