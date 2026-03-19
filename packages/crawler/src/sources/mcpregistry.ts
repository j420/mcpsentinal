import type { DiscoveredServer, ServerCategory } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:official-registry" });

const REGISTRY_API = "https://registry.modelcontextprotocol.io/v0.1";

interface RegistryPackage {
  registryType: string;
  identifier: string;
  version?: string;
}

interface RegistryServer {
  name: string;
  title?: string;
  description?: string;
  version?: string;
  websiteUrl?: string;
  repository?: {
    url: string;
    source?: string;
  };
  packages?: RegistryPackage[];
}

interface RegistryEntry {
  server: RegistryServer;
  _meta: {
    "io.modelcontextprotocol.registry/official": {
      status: string;
      isLatest: boolean;
      publishedAt: string;
      updatedAt: string;
    };
  };
}

interface RegistryResponse {
  servers: RegistryEntry[];
  metadata?: {
    nextCursor?: string;
    count?: number;
  };
}

export class McpRegistryCrawler implements CrawlerSource {
  name = "official-registry" as const;

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    try {
      let cursor: string | undefined;
      let hasMore = true;

      while (hasMore && (!limit || servers.length < limit)) {
        const url = cursor
          ? `${REGISTRY_API}/servers?limit=100&cursor=${encodeURIComponent(cursor)}`
          : `${REGISTRY_API}/servers?limit=100`;

        logger.info({ cursor }, "Fetching official MCP registry page");

        const response = await fetch(url, {
          headers: { Accept: "application/json" },
        });

        if (!response.ok) {
          logger.warn(
            { status: response.status },
            "Official registry request failed"
          );
          errors++;
          break;
        }

        const data = (await response.json()) as RegistryResponse;

        for (const entry of data.servers) {
          if (limit && servers.length >= limit) break;

          // Guard: _meta may be absent on community-registry entries
          const meta =
            entry._meta?.["io.modelcontextprotocol.registry/official"];
          if (!meta) {
            logger.debug(
              { name: entry.server?.name },
              "Skipping entry without official registry metadata"
            );
            continue;
          }

          // Only take the latest version of each server to avoid duplicates
          if (!meta.isLatest) continue;

          const s = entry.server;

          const githubUrl =
            s.repository?.url?.includes("github.com")
              ? this.normalizeGithubUrl(s.repository.url)
              : null;

          const npmPackage =
            s.packages?.find((p) => p.registryType === "npm")?.identifier ||
            null;

          const pypiPackage =
            s.packages?.find((p) => p.registryType === "pypi")?.identifier ||
            null;

          const language = npmPackage
            ? "TypeScript"
            : pypiPackage
              ? "Python"
              : null;

          servers.push({
            name: s.title || s.name,
            description: s.description || null,
            author: this.extractAuthor(s.name),
            github_url: githubUrl,
            npm_package: npmPackage,
            pypi_package: pypiPackage,
            category: this.inferCategory(s.name, s.description),
            language,
            license: null,
            source_name: "official-registry",
            source_url: `https://registry.modelcontextprotocol.io/servers/${encodeURIComponent(s.name)}`,
            external_id: s.name,
            raw_metadata: {
              qualified_name: s.name,
              version: s.version,
              website_url: s.websiteUrl,
              status: meta.status,
              published_at: meta.publishedAt,
              updated_at: meta.updatedAt,
              has_remote: !!s.websiteUrl,
              packages: s.packages?.map((p) => ({
                registry: p.registryType,
                id: p.identifier,
              })),
            },
          });
        }

        cursor = data.metadata?.nextCursor;
        hasMore = !!cursor;

        await new Promise((r) => setTimeout(r, 300));
      }
    } catch (err) {
      logger.error({ err }, "Official registry crawl error");
      errors++;
    }

    return {
      source: "official-registry",
      servers_found: servers.length,
      new_unique: servers.length,
      duplicates: 0,
      errors,
      elapsed_ms: Date.now() - start,
      servers,
    };
  }

  /** Extract org/author from qualified name like "ai.exa/exa" → "exa" */
  private extractAuthor(qualifiedName: string): string | null {
    const slash = qualifiedName.indexOf("/");
    if (slash === -1) return null;
    const namespace = qualifiedName.substring(0, slash);
    const parts = namespace.split(".");
    return parts[parts.length - 1] || null;
  }

  private normalizeGithubUrl(url: string): string | null {
    const match = url.match(/github\.com\/([^/]+\/[^/]+)/);
    if (match) {
      return `https://github.com/${match[1].replace(/\.git$/, "")}`;
    }
    return null;
  }

  private inferCategory(
    name: string,
    description?: string
  ): ServerCategory | null {
    const text = `${name} ${description || ""}`.toLowerCase();

    const categories: [ServerCategory, string[]][] = [
      ["database", ["postgres", "mysql", "sqlite", "mongo", "redis", "database", "sql"]],
      ["filesystem", ["filesystem", "file-system", "files", "directory"]],
      ["api-integration", ["api", "slack", "github", "jira", "notion", "stripe", "salesforce"]],
      ["dev-tools", ["dev-tool", "linter", "formatter", "debug", "git", "code"]],
      ["ai-ml", ["openai", "anthropic", "llm", "embedding", "ml", "ai", "trading", "signals"]],
      ["communication", ["email", "chat", "sms", "discord", "teams"]],
      ["cloud-infra", ["aws", "gcp", "azure", "docker", "kubernetes"]],
      ["security", ["security", "auth", "vault", "secrets", "compliance"]],
      ["search", ["search", "elasticsearch", "knowledge"]],
      ["browser-web", ["browser", "puppeteer", "playwright", "scrape", "web"]],
      ["code-execution", ["execute", "sandbox", "shell", "terminal"]],
      ["monitoring", ["monitor", "logs", "metrics", "alert", "analytics"]],
    ];

    for (const [cat, keywords] of categories) {
      if (keywords.some((k) => text.includes(k))) return cat;
    }
    return null;
  }
}
