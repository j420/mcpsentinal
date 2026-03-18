import type { DiscoveredServer } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:pulsemcp" });

const PULSEMCP_API = "https://api.pulsemcp.com/v0beta";

interface PulseMCPServer {
  name: string;
  short_description?: string;
  url?: string;
  source_code_url?: string;
  package_registry?: string;
  package_name?: string;
  github_stars?: number;
  integrations?: unknown[];
}

interface PulseMCPResponse {
  servers: PulseMCPServer[];
  total_count?: number;
  next?: string;
}

export class PulseMCPCrawler implements CrawlerSource {
  name = "pulsemcp" as const;

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      const PAGE_SIZE = 250;
      let offset = 0;
      let hasMore = true;

      while (hasMore && (!limit || servers.length < limit)) {
        const url = `${PULSEMCP_API}/servers?count_per_page=${PAGE_SIZE}&offset=${offset}`;

        logger.info({ offset }, "Fetching PulseMCP servers");

        const response = await fetch(url, {
          headers: {
            Accept: "application/json",
            "User-Agent": "mcp-sentinel-crawler/1.0",
          },
        });

        if (!response.ok) {
          const body = await response.text().catch(() => "");
          logger.warn(
            { status: response.status, body },
            "PulseMCP request failed"
          );
          errors++;
          break;
        }

        const data = (await response.json()) as PulseMCPResponse;

        for (const server of data.servers) {
          // source_code_url is the repo link; url is the server homepage
          const repoUrl = server.source_code_url || server.url;
          const githubUrl = repoUrl?.includes("github.com") ? repoUrl : null;

          const npmPackage =
            server.package_registry === "npm" && server.package_name
              ? server.package_name
              : null;

          servers.push({
            name: server.name,
            description: server.short_description || null,
            author: null,
            github_url: githubUrl,
            npm_package: npmPackage,
            pypi_package: null,
            category: null,
            language: null,
            license: null,
            source_name: "pulsemcp",
            source_url: `https://pulsemcp.com/servers`,
            external_id: server.name,
            raw_metadata: {
              github_stars: server.github_stars,
              url: server.url,
              package_registry: server.package_registry,
              package_name: server.package_name,
            },
          });
        }

        offset += data.servers.length;
        hasMore = !!data.next && data.servers.length === PAGE_SIZE;

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

}
