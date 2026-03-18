/**
 * ModelcontextprotocolRepoCrawler
 *
 * Crawls the canonical `modelcontextprotocol/servers` GitHub monorepo, which
 * contains Anthropic's official reference MCP server implementations (filesystem,
 * postgres, slack, git, puppeteer, …).
 *
 * This source is DISTINCT from `registry.modelcontextprotocol.io` (covered by
 * McpRegistryCrawler). The monorepo predates the registry API and contains the
 * gold-standard reference implementations that should be in our DB with the
 * highest trust signal.
 *
 * Strategy:
 *   1. Fetch `src/` directory listing via GitHub Contents API.
 *   2. For each sub-directory (one reference server each):
 *      a. Try to fetch `package.json` (TypeScript servers).
 *      b. Fall back to `pyproject.toml` minimal parse (Python servers).
 *      c. Fall back to directory name if neither exists.
 *   3. Emit one `DiscoveredServer` per directory with:
 *      - `source_name: "official-registry"` (semantically correct — these ARE official)
 *      - `github_url: null`  (monorepo root would collide across servers during dedup)
 *      - `npm_package` from package.json name (primary dedup key)
 *      - `raw_metadata.monorepo_path` so the scan pipeline can fetch source code
 *        from the correct subdirectory.
 *
 * Rate-limit handling:
 *   - Authenticated requests: 5,000 req/hour (≈100 servers × 3 API calls = 300 calls)
 *   - Unauthenticated: 60 req/hour — emits a warning, still works for small src/.
 *   - Concurrent batch size: 3 parallel directory fetches to stay well inside limits.
 *   - 300 ms pause between batches.
 */

import type { DiscoveredServer, ServerCategory } from "@mcp-sentinel/database";
import pino from "pino";
import type { CrawlerSource, CrawlResult, CrawlOptions } from "../types.js";

const logger = pino({ name: "crawler:modelcontextprotocol-repo" });

const GITHUB_API = "https://api.github.com";
const OWNER = "modelcontextprotocol";
const REPO = "servers";
const SRC_PATH = "src";
const DEFAULT_BRANCH = "main";
const BATCH_SIZE = 3;
const BATCH_DELAY_MS = 300;

// ─── GitHub API types ─────────────────────────────────────────────────────────

interface GitHubContentItem {
  name: string;
  path: string;
  type: "file" | "dir" | "symlink" | "submodule";
  sha: string;
  html_url: string;
  download_url: string | null;
}

interface GitHubFileContent {
  encoding: "base64" | "none";
  content: string;
}

// ─── Minimal manifest types ───────────────────────────────────────────────────

interface PackageJson {
  name?: string;
  description?: string;
  version?: string;
  keywords?: string[];
  license?: string;
  author?: string | { name?: string };
}

interface PyprojectFields {
  name?: string;
  description?: string;
  version?: string;
}

// ─── Crawler ──────────────────────────────────────────────────────────────────

export class ModelcontextprotocolRepoCrawler implements CrawlerSource {
  /**
   * Shares source_name with McpRegistryCrawler. Both are semantically correct
   * "official-registry" sources; the `external_id` field distinguishes them in
   * the `sources` table (UNIQUE constraint is on server_id + source_name + external_id).
   */
  name = "official-registry" as const;

  private readonly token: string | undefined;

  constructor(token?: string) {
    // Allow injection in tests; fall back to env in production.
    this.token = token ?? process.env.GITHUB_TOKEN;
  }

  async crawl(options?: CrawlOptions): Promise<CrawlResult> {
    const limit = options?.limit;
    const start = Date.now();
    const servers: DiscoveredServer[] = [];
    let errors = 0;

    if (!this.token) {
      logger.warn(
        "GITHUB_TOKEN not set — GitHub rate limit is 60 req/hour for unauthenticated requests. " +
          "Set GITHUB_TOKEN to avoid hitting limits for the monorepo crawl."
      );
    }

    try {
      // Step 1: list the src/ directory
      const srcItems = await this.fetchContents(SRC_PATH);
      const serverDirs = srcItems.filter((item) => item.type === "dir");

      logger.info(
        {
          total_items: srcItems.length,
          server_dirs: serverDirs.length,
          skipped_non_dirs: srcItems.length - serverDirs.length,
        },
        "Fetched modelcontextprotocol/servers src/ directory listing"
      );

      // Step 2: process each directory in bounded-concurrency batches
      const maxDirs = limit ? serverDirs.slice(0, limit) : serverDirs;
      for (let i = 0; i < maxDirs.length; i += BATCH_SIZE) {
        const batch = maxDirs.slice(i, i + BATCH_SIZE);

        const results = await Promise.allSettled(
          batch.map((dir) => this.processServerDir(dir))
        );

        for (let j = 0; j < results.length; j++) {
          const result = results[j];
          const dir = batch[j];

          if (result.status === "fulfilled" && result.value !== null) {
            servers.push(result.value);
            logger.debug(
              { dir: dir.name, server_name: result.value.name },
              "Processed reference server directory"
            );
          } else if (result.status === "rejected") {
            errors++;
            logger.warn(
              { dir: dir.name, err: result.reason },
              "Failed to process reference server directory — skipping"
            );
          }
        }

        // Pause between batches to respect rate limits
        if (i + BATCH_SIZE < maxDirs.length) {
          await new Promise((r) => setTimeout(r, BATCH_DELAY_MS));
        }
      }
    } catch (err) {
      logger.error(
        { err },
        "Fatal error fetching modelcontextprotocol/servers src/ listing"
      );
      errors++;
    }

    const elapsed_ms = Date.now() - start;
    logger.info(
      {
        source: "official-registry",
        servers_found: servers.length,
        new_unique: servers.length,
        duplicates: 0,
        errors,
        elapsed_ms,
      },
      "modelcontextprotocol/servers monorepo crawl complete"
    );

    return {
      source: "official-registry",
      servers_found: servers.length,
      new_unique: servers.length,
      duplicates: 0,
      errors,
      elapsed_ms,
      servers,
    };
  }

  // ─── Directory processing ─────────────────────────────────────────────────

  private async processServerDir(
    dir: GitHubContentItem
  ): Promise<DiscoveredServer | null> {
    const dirPath = `${SRC_PATH}/${dir.name}`;
    const treeUrl = `https://github.com/${OWNER}/${REPO}/tree/${DEFAULT_BRANCH}/${dirPath}`;

    // Attempt TypeScript manifest first, then Python
    const pkgJson = await this.tryFetchPackageJson(dirPath);
    const pyproject = pkgJson === null ? await this.tryFetchPyprojectToml(dirPath) : null;

    const isTypeScript = pkgJson !== null;
    const isPython = !isTypeScript && pyproject !== null;

    // Canonical name: prefer manifest name, fall back to derived name
    const name =
      pkgJson?.name ??
      pyproject?.name ??
      `mcp-server-${dir.name}`;

    const description =
      pkgJson?.description ?? pyproject?.description ?? null;

    const version = pkgJson?.version ?? pyproject?.version ?? null;

    const license =
      typeof pkgJson?.license === "string" ? pkgJson.license : null;

    const authorRaw = pkgJson?.author;
    const author =
      typeof authorRaw === "string"
        ? authorRaw
        : typeof authorRaw === "object" && authorRaw !== null
          ? (authorRaw.name ?? "Anthropic")
          : "Anthropic";

    // npm_package is the primary dedup key across sources for TypeScript servers
    const npmPackage = isTypeScript ? (pkgJson?.name ?? null) : null;

    return {
      name,
      description,
      author,
      // Do NOT set github_url to the monorepo root — all servers would share
      // the same URL and be collapsed into one record by the dedup key.
      // The actual code location is in raw_metadata.github_tree_url.
      github_url: null,
      npm_package: npmPackage,
      pypi_package: null, // pypi name extraction is a Layer 2 enrichment step
      category: this.inferCategory(dir.name, description),
      language: isTypeScript ? "TypeScript" : isPython ? "Python" : null,
      license,
      source_name: "official-registry",
      source_url: treeUrl,
      // Unique identifier for this source record in the sources table
      external_id: `${OWNER}/${REPO}/${dirPath}`,
      raw_metadata: {
        monorepo: `${OWNER}/${REPO}`,
        src_path: dirPath,
        github_tree_url: treeUrl,
        is_reference_implementation: true,
        dir_name: dir.name,
        dir_sha: dir.sha,
        version,
        keywords: pkgJson?.keywords ?? [],
      },
    };
  }

  // ─── GitHub API helpers ───────────────────────────────────────────────────

  private async fetchContents(path: string): Promise<GitHubContentItem[]> {
    const url = `${GITHUB_API}/repos/${OWNER}/${REPO}/contents/${path}`;
    const response = await this.githubFetch(url);

    if (!response.ok) {
      throw new Error(
        `GitHub Contents API returned HTTP ${response.status} for path "${path}" in ${OWNER}/${REPO}`
      );
    }

    return response.json() as Promise<GitHubContentItem[]>;
  }

  /**
   * Returns the parsed package.json, or null if the file doesn't exist.
   * Throws on unexpected API errors (non-404).
   */
  private async tryFetchPackageJson(dirPath: string): Promise<PackageJson | null> {
    const url = `${GITHUB_API}/repos/${OWNER}/${REPO}/contents/${dirPath}/package.json`;
    const response = await this.githubFetch(url);

    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(
        `GitHub API returned HTTP ${response.status} fetching package.json at ${dirPath}`
      );
    }

    const file = (await response.json()) as GitHubFileContent;
    if (file.encoding !== "base64") {
      logger.warn({ dirPath }, "Unexpected encoding for package.json — skipping");
      return null;
    }

    try {
      const raw = Buffer.from(file.content.replace(/\n/g, ""), "base64").toString("utf-8");
      return JSON.parse(raw) as PackageJson;
    } catch (err) {
      logger.warn({ dirPath, err }, "Failed to parse package.json — skipping");
      return null;
    }
  }

  /**
   * Minimal TOML parser for [project] table — only extracts name, description, version.
   * Full TOML parsing is not worth the dependency for these three fields.
   * Returns null if the file doesn't exist.
   */
  private async tryFetchPyprojectToml(dirPath: string): Promise<PyprojectFields | null> {
    const url = `${GITHUB_API}/repos/${OWNER}/${REPO}/contents/${dirPath}/pyproject.toml`;
    const response = await this.githubFetch(url);

    if (response.status === 404) return null;
    if (!response.ok) return null; // Non-fatal: fall back to dir name

    const file = (await response.json()) as GitHubFileContent;
    if (file.encoding !== "base64") return null;

    try {
      const raw = Buffer.from(file.content.replace(/\n/g, ""), "base64").toString("utf-8");

      // Scope matching to the [project] section to avoid false matches
      // from other TOML tables (e.g., [tool.poetry]).
      // Use lookahead so we don't consume the next section header.
      // `$` without the `m` flag matches end-of-string in JS.
      const projectSection = raw.match(/\[project\]([\s\S]*?)(?=\n\[|$)/)?.[1] ?? raw;

      const name = projectSection.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1] ?? undefined;
      const description =
        projectSection.match(/^\s*description\s*=\s*"([^"]+)"/m)?.[1] ?? undefined;
      const version =
        projectSection.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1] ?? undefined;

      return { name, description, version };
    } catch {
      return null;
    }
  }

  private async githubFetch(url: string): Promise<Response> {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "mcp-sentinel-crawler/0.1.0",
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    return fetch(url, { headers });
  }

  // ─── Category inference ───────────────────────────────────────────────────

  private inferCategory(
    dirName: string,
    description: string | null
  ): ServerCategory | null {
    const text = `${dirName} ${description ?? ""}`.toLowerCase();

    const categories: [ServerCategory, string[]][] = [
      ["database", ["postgres", "mysql", "sqlite", "mongo", "redis", "sql", "database"]],
      ["filesystem", ["filesystem", "file", "directory", "storage", "drive"]],
      ["api-integration", [
        "github", "gitlab", "jira", "notion", "stripe", "slack", "sentry",
        "maps", "gdrive", "google", "salesforce",
      ]],
      ["dev-tools", ["git", "linter", "formatter", "debug", "code", "sequential"]],
      ["ai-ml", ["openai", "anthropic", "llm", "embedding", "memory", "thinking"]],
      ["communication", ["email", "chat", "sms", "discord", "teams", "slack"]],
      ["cloud-infra", ["aws", "gcp", "azure", "docker", "kubernetes"]],
      ["security", ["security", "auth", "vault", "secrets"]],
      ["search", ["search", "brave", "knowledge", "everything"]],
      ["browser-web", ["browser", "puppeteer", "playwright", "fetch", "web", "scrape"]],
      ["code-execution", ["execute", "sandbox", "shell", "terminal"]],
      ["monitoring", ["monitor", "logs", "metrics", "time", "alert"]],
    ];

    for (const [cat, keywords] of categories) {
      if (keywords.some((k) => text.includes(k))) return cat;
    }
    return null;
  }
}
