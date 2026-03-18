import type { DiscoveredServer, ServerCategory } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:pypi" });

const PYPI_SEARCH_PREFIXES = [
  "mcp-server-",
  "mcp_server_",
  "fastmcp-",
];

const PYPI_API = "https://pypi.org/pypi";

interface PyPIPackageInfo {
  info: {
    name: string;
    version: string;
    summary: string;
    description: string;
    author: string;
    author_email: string;
    license: string;
    home_page: string;
    project_urls: Record<string, string>;
    keywords: string;
    classifiers: string[];
  };
}

export class PyPICrawler implements CrawlerSource {
  name = "pypi" as const;

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    const seen = new Set<string>();
    let errors = 0;

    // PyPI doesn't have a search API — use the simple index and filter
    // For now, we use the XML-RPC search and known prefix patterns
    try {
      // Approach 1: Search via simple API listing
      const response = await fetch("https://pypi.org/simple/", {
        headers: { Accept: "application/vnd.pypi.simple.v1+json" },
      });

      if (response.ok) {
        const data = (await response.json()) as { projects: Array<{ name: string }> };

        const mcpPackages = data.projects.filter((p) =>
          PYPI_SEARCH_PREFIXES.some((prefix) =>
            p.name.toLowerCase().startsWith(prefix)
          ) || p.name.toLowerCase().includes("mcp-server")
        );

        logger.info(
          { count: mcpPackages.length },
          "Found MCP-related PyPI packages"
        );

        for (const pkg of mcpPackages) {
          if (limit && servers.length >= limit) break;
          if (seen.has(pkg.name)) continue;
          seen.add(pkg.name);

          try {
            const pkgInfo = await this.fetchPackageInfo(pkg.name);
            if (!pkgInfo) continue;

            const githubUrl = this.extractGithubUrl(pkgInfo);

            servers.push({
              name: pkg.name,
              description: pkgInfo.info.summary || null,
              author: pkgInfo.info.author || null,
              github_url: githubUrl,
              npm_package: null,
              pypi_package: pkg.name,
              category: this.inferCategory(pkg.name, pkgInfo.info.summary, pkgInfo.info.keywords),
              language: "Python",
              license: pkgInfo.info.license || null,
              source_name: "pypi",
              source_url: `https://pypi.org/project/${pkg.name}/`,
              external_id: pkg.name,
              raw_metadata: {
                version: pkgInfo.info.version,
                classifiers: pkgInfo.info.classifiers,
                keywords: pkgInfo.info.keywords,
              },
            });

            // Rate limit
            await new Promise((r) => setTimeout(r, 100));
          } catch (err) {
            logger.warn({ package: pkg.name, err }, "Failed to fetch package info");
            errors++;
          }
        }
      } else {
        logger.warn({ status: response.status }, "PyPI simple index fetch failed");
        errors++;
      }
    } catch (err) {
      logger.error({ err }, "PyPI crawl error");
      errors++;
    }

    return {
      source: "pypi",
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
    description?: string,
    keywords?: string
  ): ServerCategory | null {
    const text = `${name} ${description || ""} ${keywords || ""}`.toLowerCase();

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

    for (const [cat, kws] of categories) {
      if (kws.some((k) => text.includes(k))) return cat;
    }
    return null;
  }

  private async fetchPackageInfo(
    name: string
  ): Promise<PyPIPackageInfo | null> {
    const response = await fetch(`${PYPI_API}/${name}/json`);
    if (!response.ok) return null;
    return (await response.json()) as PyPIPackageInfo;
  }

  private extractGithubUrl(pkgInfo: PyPIPackageInfo): string | null {
    const urls = pkgInfo.info.project_urls || {};
    for (const [, url] of Object.entries(urls)) {
      if (url?.includes("github.com")) {
        const match = url.match(/github\.com\/([^/]+\/[^/]+)/);
        if (match) {
          return `https://github.com/${match[1].replace(/\.git$/, "")}`;
        }
      }
    }

    if (pkgInfo.info.home_page?.includes("github.com")) {
      const match = pkgInfo.info.home_page.match(
        /github\.com\/([^/]+\/[^/]+)/
      );
      if (match) {
        return `https://github.com/${match[1].replace(/\.git$/, "")}`;
      }
    }

    return null;
  }
}
