import type { DiscoveredServer } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult } from "../types.js";

const logger = pino({ name: "crawler:github" });

const GITHUB_SEARCH_QUERIES = [
  "topic:mcp-server",
  "mcp-server in:name",
  '"model context protocol" in:readme',
  "FastMCP in:readme language:python",
  "FastMCP in:readme language:typescript",
  '"@modelcontextprotocol/sdk" in:file',
];

const GITHUB_API = "https://api.github.com";

interface GitHubSearchResult {
  total_count: number;
  items: Array<{
    id: number;
    full_name: string;
    name: string;
    description: string | null;
    html_url: string;
    stargazers_count: number;
    forks_count: number;
    language: string | null;
    license: { spdx_id: string } | null;
    owner: { login: string };
    pushed_at: string;
    topics: string[];
    archived: boolean;
    fork: boolean;
  }>;
}

export class GitHubCrawler implements CrawlerSource {
  name = "github" as const;
  private token: string | undefined;

  constructor() {
    this.token = process.env.GITHUB_TOKEN;
  }

  async crawl(): Promise<CrawlResult> {
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    const seen = new Set<string>();
    let errors = 0;

    if (!this.token) {
      logger.warn(
        "GITHUB_TOKEN not set — rate limited to 10 req/min"
      );
    }

    for (const query of GITHUB_SEARCH_QUERIES) {
      try {
        let page = 1;
        let hasMore = true;

        while (hasMore && page <= 10) {
          const url = `${GITHUB_API}/search/repositories?q=${encodeURIComponent(query)}&per_page=100&page=${page}&sort=stars&order=desc`;
          logger.info({ query, page }, "Fetching GitHub search");

          const headers: Record<string, string> = {
            Accept: "application/vnd.github.v3+json",
            "User-Agent": "mcp-sentinel-crawler/0.1.0",
          };
          if (this.token) {
            headers.Authorization = `Bearer ${this.token}`;
          }

          const response = await fetch(url, { headers });

          if (response.status === 403) {
            logger.warn("GitHub rate limit hit, backing off");
            await new Promise((r) => setTimeout(r, 60_000));
            continue;
          }

          if (!response.ok) {
            logger.warn(
              { status: response.status, query },
              "GitHub search failed"
            );
            errors++;
            break;
          }

          const data = (await response.json()) as GitHubSearchResult;

          for (const repo of data.items) {
            if (repo.archived || repo.fork) continue;
            if (seen.has(repo.full_name)) continue;
            seen.add(repo.full_name);

            servers.push({
              name: repo.name,
              description: repo.description,
              author: repo.owner.login,
              github_url: repo.html_url,
              npm_package: null,
              pypi_package: null,
              category: this.inferCategory(
                repo.name,
                repo.description,
                repo.topics
              ),
              language: repo.language,
              license: repo.license?.spdx_id || null,
              source_name: "github",
              source_url: repo.html_url,
              external_id: repo.full_name,
              raw_metadata: {
                stars: repo.stargazers_count,
                forks: repo.forks_count,
                topics: repo.topics,
                pushed_at: repo.pushed_at,
              },
            });
          }

          hasMore = data.items.length === 100;
          page++;

          // GitHub search API: 30 req/min with auth, 10 without
          await new Promise((r) =>
            setTimeout(r, this.token ? 2_000 : 6_000)
          );
        }
      } catch (err) {
        logger.error({ query, err }, "GitHub crawl error");
        errors++;
      }
    }

    return {
      source: "github",
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
    description: string | null,
    topics: string[]
  ): string | null {
    const text = `${name} ${description || ""} ${topics.join(" ")}`.toLowerCase();

    const categories: [string, string[]][] = [
      ["database", ["postgres", "mysql", "sqlite", "mongo", "redis", "database", "sql", "db"]],
      ["filesystem", ["filesystem", "file-system", "files", "directory"]],
      ["api-integration", ["api", "slack", "github", "jira", "notion", "stripe", "twilio"]],
      ["dev-tools", ["dev-tool", "linter", "formatter", "debug", "git"]],
      ["ai-ml", ["openai", "anthropic", "llm", "embedding", "ml", "ai"]],
      ["communication", ["email", "chat", "sms", "slack", "discord", "teams"]],
      ["cloud-infra", ["aws", "gcp", "azure", "docker", "kubernetes", "terraform"]],
      ["security", ["security", "auth", "vault", "secrets", "encrypt"]],
      ["search", ["search", "elasticsearch", "algolia", "brave-search"]],
      ["browser-web", ["browser", "puppeteer", "playwright", "scrape", "web"]],
      ["code-execution", ["execute", "sandbox", "eval", "shell", "terminal"]],
      ["monitoring", ["monitor", "logs", "metrics", "alert", "observ"]],
    ];

    for (const [cat, keywords] of categories) {
      if (keywords.some((k) => text.includes(k))) return cat;
    }
    return null;
  }
}
