import type { DiscoveredServer, ServerCategory } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:smithery" });

const SMITHERY_API = "https://registry.smithery.ai";

interface SmitheryServer {
  qualifiedName: string;
  displayName: string;
  description?: string;
  homepage?: string;
  repository?: string;
  iconUrl?: string;
  useCount?: number;
  isDeployed?: boolean;
  createdAt?: string;
}

interface SmitheryResponse {
  servers: SmitheryServer[];
  pagination?: {
    currentPage: number;
    pageSize: number;
    totalPages: number;
    totalCount: number;
  };
}

export class SmitheryCrawler implements CrawlerSource {
  name = "smithery" as const;

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      const PAGE_SIZE = 100;
      let page = 1;
      let totalPages = 1;

      while (page <= totalPages && (!limit || servers.length < limit)) {
        const params = new URLSearchParams({
          pageSize: String(PAGE_SIZE),
          page: String(page),
        });

        const url = `${SMITHERY_API}/servers?${params}`;
        logger.info({ page, totalPages }, "Fetching Smithery servers");

        const headers: Record<string, string> = { Accept: "application/json" };
        const apiKey = process.env.SMITHERY_API_KEY;
        if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

        const response = await fetch(url, { headers });

        if (!response.ok) {
          const body = await response.text().catch(() => "");
          logger.warn({ status: response.status, body }, "Smithery request failed");
          errors++;
          break;
        }

        const data = (await response.json()) as SmitheryResponse;

        if (data.pagination) {
          totalPages = data.pagination.totalPages;
        }

        for (const server of data.servers) {
          if (limit && servers.length >= limit) break;

          const githubUrl = server.repository?.includes("github.com")
            ? server.repository
            : null;

          // Infer language from scoped npm package names (e.g. "@org/pkg" → TypeScript)
          const language = server.qualifiedName?.startsWith("@")
            ? "TypeScript"
            : null;

          servers.push({
            name: server.displayName || server.qualifiedName,
            description: server.description || null,
            author: null,
            github_url: githubUrl,
            npm_package: null,
            pypi_package: null,
            category: this.inferCategory(server.displayName || server.qualifiedName, server.description),
            language,
            license: null,
            source_name: "smithery",
            source_url: `https://smithery.ai/server/${server.qualifiedName}`,
            external_id: server.qualifiedName,
            raw_metadata: {
              homepage: server.homepage,
              qualifiedName: server.qualifiedName,
              useCount: server.useCount,
              isDeployed: server.isDeployed,
            },
          });
        }

        page++;
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

  private inferCategory(
    name: string,
    description?: string
  ): ServerCategory | null {
    const text = `${name} ${description || ""}`.toLowerCase();

    const categories: [ServerCategory, string[]][] = [
      ["database", ["postgres", "mysql", "sqlite", "mongo", "redis", "database", "sql", "supabase", "prisma"]],
      ["filesystem", ["filesystem", "file-system", "files", "directory", "storage", "drive"]],
      ["api-integration", ["api", "slack", "github", "jira", "notion", "stripe", "twilio", "salesforce", "zapier", "webhook"]],
      ["dev-tools", ["dev-tool", "linter", "formatter", "debug", "git", "code", "lint", "test"]],
      ["ai-ml", ["openai", "anthropic", "llm", "embedding", "ml", "ai", "gpt", "claude", "gemini", "model"]],
      ["communication", ["email", "chat", "sms", "slack", "discord", "teams", "telegram"]],
      ["cloud-infra", ["aws", "gcp", "azure", "docker", "kubernetes", "terraform", "cloudflare"]],
      ["security", ["security", "auth", "vault", "secrets", "encrypt", "compliance"]],
      ["search", ["search", "elasticsearch", "algolia", "brave-search", "knowledge"]],
      ["browser-web", ["browser", "puppeteer", "playwright", "scrape", "web", "crawl"]],
      ["code-execution", ["execute", "sandbox", "eval", "shell", "terminal", "python sandbox"]],
      ["monitoring", ["monitor", "logs", "metrics", "alert", "observ", "analytics"]],
    ];

    for (const [cat, keywords] of categories) {
      if (keywords.some((k) => text.includes(k))) return cat;
    }
    return null;
  }
}
