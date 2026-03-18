import type { DiscoveredServer, ServerCategory } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:npm" });

const NPM_SEARCH_QUERIES = [
  "mcp-server",
  "mcp server",
  "@modelcontextprotocol",
  "fastmcp",
];

const NPM_REGISTRY_URL = "https://registry.npmjs.org";
const NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search";

interface NpmSearchResult {
  objects: Array<{
    package: {
      name: string;
      version: string;
      description?: string;
      keywords?: string[];
      author?: { name?: string; email?: string };
      links: {
        npm?: string;
        homepage?: string;
        repository?: string;
        bugs?: string;
      };
      publisher?: { username: string };
    };
    score: {
      final: number;
      detail: {
        quality: number;
        popularity: number;
        maintenance: number;
      };
    };
  }>;
  total: number;
}

export class NpmCrawler implements CrawlerSource {
  name = "npm" as const;

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    const seen = new Set<string>();
    let errors = 0;

    for (const query of NPM_SEARCH_QUERIES) {
      if (limit && servers.length >= limit) break;
      try {
        let from = 0;
        const size = 250;
        let hasMore = true;

        while (hasMore && (!limit || servers.length < limit)) {
          const url = `${NPM_SEARCH_URL}?text=${encodeURIComponent(query)}&size=${size}&from=${from}`;
          logger.info({ query, from }, "Fetching npm search results");

          const response = await fetch(url, {
            headers: { Accept: "application/json" },
          });

          if (!response.ok) {
            logger.warn(
              { status: response.status, query },
              "npm search request failed"
            );
            errors++;
            break;
          }

          const data = (await response.json()) as NpmSearchResult;

          for (const obj of data.objects) {
            if (limit && servers.length >= limit) break;

            const pkg = obj.package;
            if (seen.has(pkg.name)) continue;
            seen.add(pkg.name);

            // Filter: must be MCP-related
            const isMcp =
              pkg.name.includes("mcp") ||
              pkg.keywords?.some((k) =>
                k.toLowerCase().includes("mcp")
              ) ||
              pkg.description?.toLowerCase().includes("mcp server") ||
              pkg.description
                ?.toLowerCase()
                .includes("model context protocol");

            if (!isMcp) continue;

            const githubUrl = this.extractGithubUrl(pkg.links.repository);

            servers.push({
              name: pkg.name,
              description: pkg.description || null,
              author:
                pkg.author?.name || pkg.publisher?.username || null,
              github_url: githubUrl,
              npm_package: pkg.name,
              pypi_package: null,
              category: this.inferCategory(pkg.name, pkg.description, pkg.keywords),
              language: "TypeScript",
              license: null,
              source_name: "npm",
              source_url: pkg.links.npm || `https://www.npmjs.com/package/${pkg.name}`,
              external_id: pkg.name,
              raw_metadata: {
                version: pkg.version,
                keywords: pkg.keywords,
                score: obj.score,
              },
            });
          }

          from += size;
          hasMore = data.objects.length === size && from < data.total;

          // Rate limit: wait between requests
          await new Promise((resolve) => setTimeout(resolve, 200));
        }
      } catch (err) {
        logger.error({ query, err }, "npm crawl error");
        errors++;
      }
    }

    return {
      source: "npm",
      servers_found: servers.length,
      new_unique: servers.length, // dedup happens at ingestion
      duplicates: 0,
      errors,
      elapsed_ms: Date.now() - start,
      servers,
    };
  }

  private inferCategory(
    name: string,
    description?: string,
    keywords?: string[]
  ): ServerCategory | null {
    const text = `${name} ${description || ""} ${(keywords || []).join(" ")}`.toLowerCase();

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

    for (const [cat, keywords_] of categories) {
      if (keywords_.some((k) => text.includes(k))) return cat;
    }
    return null;
  }

  private extractGithubUrl(
    repoUrl: string | undefined
  ): string | null {
    if (!repoUrl) return null;
    const match = repoUrl.match(
      /github\.com\/([^/]+\/[^/]+)/
    );
    if (match) {
      return `https://github.com/${match[1].replace(/\.git$/, "")}`;
    }
    return null;
  }
}
