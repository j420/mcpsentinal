import type { DiscoveredServer } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult } from "../types.js";

const logger = pino({ name: "crawler:pulsemcp" });

const PULSEMCP_API = "https://api.pulsemcp.com/v0beta1";

interface PulseMCPServer {
  name: string;
  description?: string;
  source_code_url?: string;
  package_registry?: string;
  download_count?: number;
  github_stars?: number;
  security_analysis?: Record<string, unknown>;
  popularity_score?: number;
  author?: string;
  category?: string;
  created_at?: string;
  updated_at?: string;
}

interface PulseMCPResponse {
  servers: PulseMCPServer[];
  next_cursor?: string;
  total_count?: number;
}

export class PulseMCPCrawler implements CrawlerSource {
  name = "pulsemcp" as const;

  async crawl(): Promise<CrawlResult> {
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      let cursor: string | undefined;
      let hasMore = true;

      while (hasMore) {
        const url = cursor
          ? `${PULSEMCP_API}/servers?cursor=${cursor}&limit=100`
          : `${PULSEMCP_API}/servers?limit=100`;

        logger.info({ cursor }, "Fetching PulseMCP servers");

        const response = await fetch(url, {
          headers: { Accept: "application/json" },
        });

        if (!response.ok) {
          logger.warn(
            { status: response.status },
            "PulseMCP request failed"
          );
          errors++;
          break;
        }

        const data = (await response.json()) as PulseMCPResponse;

        for (const server of data.servers) {
          const githubUrl = server.source_code_url?.includes("github.com")
            ? server.source_code_url
            : null;

          const npmPackage = server.package_registry?.includes("npmjs.com")
            ? this.extractNpmPackage(server.package_registry)
            : null;

          servers.push({
            name: server.name,
            description: server.description || null,
            author: server.author || null,
            github_url: githubUrl,
            npm_package: npmPackage,
            pypi_package: null,
            category: server.category as any || null,
            language: null,
            license: null,
            source_name: "pulsemcp",
            source_url: `https://pulsemcp.com/servers`,
            external_id: server.name,
            raw_metadata: {
              download_count: server.download_count,
              github_stars: server.github_stars,
              security_analysis: server.security_analysis,
              popularity_score: server.popularity_score,
            },
          });
        }

        cursor = data.next_cursor;
        hasMore = !!cursor;

        await new Promise((r) => setTimeout(r, 500));
      }
    } catch (err) {
      logger.error({ err }, "PulseMCP crawl error");
      errors++;
    }

    return {
      source: "pulsemcp",
      servers_found: servers.length,
      new_unique: servers.length,
      duplicates: 0,
      errors,
      elapsed_ms: Date.now() - start,
      servers,
    };
  }

  private extractNpmPackage(url: string): string | null {
    const match = url.match(
      /npmjs\.com\/package\/(@?[^/]+(?:\/[^/]+)?)/
    );
    return match ? match[1] : null;
  }
}
