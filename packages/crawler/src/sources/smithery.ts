import type { DiscoveredServer } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult } from "../types.js";

const logger = pino({ name: "crawler:smithery" });

const SMITHERY_API = "https://registry.smithery.ai/api";

interface SmitheryServer {
  qualifiedName: string;
  displayName: string;
  description?: string;
  homepage?: string;
  repository?: string;
  author?: string;
  license?: string;
}

interface SmitheryResponse {
  servers: SmitheryServer[];
  pageInfo?: { hasNextPage: boolean; endCursor: string };
}

export class SmitheryCrawler implements CrawlerSource {
  name = "smithery" as const;

  async crawl(): Promise<CrawlResult> {
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      let cursor: string | undefined;
      let hasMore = true;

      while (hasMore) {
        const params = new URLSearchParams({ pageSize: "100" });
        if (cursor) params.set("cursor", cursor);

        const url = `${SMITHERY_API}/servers?${params}`;
        logger.info({ cursor }, "Fetching Smithery servers");

        const response = await fetch(url, {
          headers: { Accept: "application/json" },
        });

        if (!response.ok) {
          logger.warn({ status: response.status }, "Smithery request failed");
          errors++;
          break;
        }

        const data = (await response.json()) as SmitheryResponse;

        for (const server of data.servers) {
          const githubUrl = server.repository?.includes("github.com")
            ? server.repository
            : null;

          servers.push({
            name: server.displayName || server.qualifiedName,
            description: server.description || null,
            author: server.author || null,
            github_url: githubUrl,
            npm_package: null,
            pypi_package: null,
            category: null,
            language: null,
            license: server.license || null,
            source_name: "smithery",
            source_url: `https://smithery.ai/server/${server.qualifiedName}`,
            external_id: server.qualifiedName,
            raw_metadata: {
              homepage: server.homepage,
              qualifiedName: server.qualifiedName,
            },
          });
        }

        hasMore = data.pageInfo?.hasNextPage ?? false;
        cursor = data.pageInfo?.endCursor;

        await new Promise((r) => setTimeout(r, 300));
      }
    } catch (err) {
      logger.error({ err }, "Smithery crawl error");
      errors++;
    }

    return {
      source: "smithery",
      servers_found: servers.length,
      new_unique: servers.length,
      duplicates: 0,
      errors,
      elapsed_ms: Date.now() - start,
      servers,
    };
  }
}
