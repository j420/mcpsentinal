/**
 * P9 — Scanner Engine Engineer
 * SourceFetcher — downloads source code and dependency manifests from GitHub.
 *
 * Design principles:
 * - Uses GitHub raw content API (no auth required, but GITHUB_TOKEN raises rate limits from 60→5000 req/hour)
 * - Fetches well-known source entry points only — no recursive tree listing (saves API quota)
 * - Caps source at MAX_SOURCE_BYTES to keep analysis context bounded
 * - Gracefully degrades: partial fetches are better than no fetch
 * - Parses npm (package.json) and PyPI (pyproject.toml + requirements.txt) manifests
 * - Never throws — always returns a FetchedSource (with error set if something went wrong)
 */

import pino from "pino";
import type { RawDependency } from "./types.js";

const logger = pino({ name: "scanner:fetcher" });

/** Maximum combined source code bytes to include in the analysis context */
const MAX_SOURCE_BYTES = 50_000;

/** HTTP fetch timeout per file request */
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Well-known JavaScript/TypeScript entry point paths to try, in priority order.
 * Covers the most common MCP server project structures.
 */
const JS_ENTRY_PATHS = [
  "src/index.ts",
  "src/server.ts",
  "src/main.ts",
  "src/app.ts",
  "index.ts",
  "server.ts",
  "main.ts",
  "src/index.js",
  "src/server.js",
  "index.js",
  "server.js",
];

/**
 * Well-known Python entry point paths to try, in priority order.
 */
const PY_ENTRY_PATHS = [
  "src/server.py",
  "src/main.py",
  "src/__init__.py",
  "server.py",
  "main.py",
  "__init__.py",
  "app.py",
];

export interface FetchedSource {
  /** Concatenated source code from fetched files, null if nothing could be fetched */
  source_code: string | null;
  /** Raw dependencies parsed from package manifests (before CVE enrichment) */
  raw_dependencies: RawDependency[];
  /** List of file paths successfully fetched */
  files_fetched: string[];
  /** Non-fatal error message describing what went wrong, if anything */
  error: string | null;
}

export class SourceFetcher {
  private readonly githubToken: string | null;
  private readonly userAgent = "mcp-sentinel-scanner/1.0 (security research; contact: security@mcp-sentinel.com)";

  constructor() {
    this.githubToken = process.env.GITHUB_TOKEN ?? null;
    if (!this.githubToken) {
      logger.warn(
        "GITHUB_TOKEN not set — GitHub API limited to 60 requests/hour. " +
          "Set GITHUB_TOKEN for 5,000 req/hour."
      );
    }
  }

  /**
   * Fetch source code and dependency manifest from a GitHub repository URL.
   * Always returns a result — never throws.
   */
  async fetchFromGitHub(githubUrl: string): Promise<FetchedSource> {
    const parsed = this.parseGitHubUrl(githubUrl);
    if (!parsed) {
      return {
        source_code: null,
        raw_dependencies: [],
        files_fetched: [],
        error: `Cannot parse GitHub URL: ${githubUrl}`,
      };
    }

    const { owner, repo } = parsed;

    try {
      // Step 1: Determine default branch (main, master, etc.)
      const branch = await this.getDefaultBranch(owner, repo);

      // Step 2: Fetch package manifest to determine ecosystem + dependencies
      let rawDependencies: RawDependency[] = [];
      let isNode = false;
      let isPython = false;
      let mainEntryHint: string | null = null;
      let packageJsonContent: string | null = null;

      packageJsonContent = await this.fetchRawFile(owner, repo, branch, "package.json");
      if (packageJsonContent) {
        isNode = true;
        try {
          const pkg = JSON.parse(packageJsonContent) as Record<string, unknown>;
          rawDependencies = this.parseNpmDeps(pkg);
          // Extract main entry hint for smarter file discovery
          mainEntryHint =
            (pkg.main as string | undefined) ??
            (pkg.module as string | undefined) ??
            null;
        } catch {
          logger.warn({ owner, repo }, "package.json parse failed — deps unavailable");
        }
      }

      if (!isNode) {
        const pyproject = await this.fetchRawFile(owner, repo, branch, "pyproject.toml");
        const requirements = await this.fetchRawFile(owner, repo, branch, "requirements.txt");
        if (pyproject || requirements) {
          isPython = true;
          rawDependencies = this.parsePypiDeps(pyproject ?? "", requirements);
        }
      }

      // Step 3: Fetch source files
      const entryPaths = isNode
        ? JS_ENTRY_PATHS
        : isPython
          ? PY_ENTRY_PATHS
          : [...JS_ENTRY_PATHS, ...PY_ENTRY_PATHS];

      // If package.json specifies a main entry, prepend it so we try it first
      const priorityPaths: string[] = mainEntryHint
        ? [mainEntryHint, ...entryPaths.filter((p) => p !== mainEntryHint)]
        : entryPaths;

      const filesFetched: string[] = [];
      let combinedSource = "";

      for (const filePath of priorityPaths) {
        if (combinedSource.length >= MAX_SOURCE_BYTES) break;
        const content = await this.fetchRawFile(owner, repo, branch, filePath);
        if (content) {
          const remaining = MAX_SOURCE_BYTES - combinedSource.length;
          const chunk = content.length > remaining ? content.substring(0, remaining) : content;
          combinedSource += `\n// ═══ FILE: ${filePath} ═══\n${chunk}`;
          filesFetched.push(filePath);
        }
      }

      // Always include package.json in source — C5 (hardcoded secrets) scans it for tokens
      if (packageJsonContent && combinedSource.length < MAX_SOURCE_BYTES) {
        const remaining = MAX_SOURCE_BYTES - combinedSource.length;
        const chunk =
          packageJsonContent.length > remaining
            ? packageJsonContent.substring(0, remaining)
            : packageJsonContent;
        combinedSource += `\n// ═══ FILE: package.json ═══\n${chunk}`;
        if (!filesFetched.includes("package.json")) {
          filesFetched.push("package.json");
        }
      }

      logger.info(
        {
          owner,
          repo,
          branch,
          files: filesFetched.length,
          bytes: combinedSource.length,
          deps: rawDependencies.length,
          ecosystem: isNode ? "npm" : isPython ? "pypi" : "unknown",
        },
        "Source fetch complete"
      );

      return {
        source_code: combinedSource.length > 0 ? combinedSource : null,
        raw_dependencies: rawDependencies,
        files_fetched: filesFetched,
        error: null,
      };
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      logger.error({ owner, repo, error }, "Source fetch failed");
      return { source_code: null, raw_dependencies: [], files_fetched: [], error };
    }
  }

  // ─── Private Helpers ───────────────────────────────────────────────────────

  /**
   * Parse a GitHub URL into owner/repo.
   * Handles: https://github.com/owner/repo, https://github.com/owner/repo.git,
   *          github.com/owner/repo, etc.
   */
  private parseGitHubUrl(url: string): { owner: string; repo: string } | null {
    try {
      const normalized = url.replace(/\.git$/, "").replace(/\/$/, "");
      const u = new URL(normalized.startsWith("http") ? normalized : `https://${normalized}`);
      if (!u.hostname.includes("github.com")) return null;
      const parts = u.pathname.split("/").filter(Boolean);
      if (parts.length < 2) return null;
      return { owner: parts[0], repo: parts[1] };
    } catch {
      return null;
    }
  }

  /**
   * Retrieve the default branch name for a repository.
   * Falls back to "main" if the API call fails.
   */
  private async getDefaultBranch(owner: string, repo: string): Promise<string> {
    try {
      const data = await this.githubApiGet(
        `https://api.github.com/repos/${owner}/${repo}`
      );
      if (data && typeof data === "object" && "default_branch" in data) {
        return (data as Record<string, string>).default_branch;
      }
    } catch {
      // Silently fall through — "main" is the correct default for most repos
    }
    return "main";
  }

  /**
   * Fetch a single raw file from GitHub.
   * Returns null if the file doesn't exist or the request fails.
   */
  private async fetchRawFile(
    owner: string,
    repo: string,
    branch: string,
    filePath: string
  ): Promise<string | null> {
    const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;
    try {
      const headers: Record<string, string> = { "User-Agent": this.userAgent };
      if (this.githubToken) {
        headers["Authorization"] = `Bearer ${this.githubToken}`;
      }
      const resp = await fetch(url, {
        headers,
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!resp.ok) return null;
      return await resp.text();
    } catch {
      return null;
    }
  }

  /**
   * Make an authenticated GitHub API GET request and parse JSON.
   */
  private async githubApiGet(url: string): Promise<unknown> {
    const headers: Record<string, string> = {
      "User-Agent": this.userAgent,
      Accept: "application/vnd.github.v3+json",
    };
    if (this.githubToken) {
      headers["Authorization"] = `Bearer ${this.githubToken}`;
    }
    const resp = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!resp.ok) {
      throw new Error(`GitHub API responded ${resp.status} for ${url}`);
    }
    return resp.json();
  }

  /**
   * Parse npm dependencies from a parsed package.json object.
   * Includes: dependencies, devDependencies, peerDependencies, optionalDependencies.
   * Strips semver range prefixes (^, ~, >=, etc.) to get the base version.
   */
  private parseNpmDeps(pkg: Record<string, unknown>): RawDependency[] {
    const deps: RawDependency[] = [];
    const seen = new Set<string>();

    const sections = [
      "dependencies",
      "devDependencies",
      "peerDependencies",
      "optionalDependencies",
    ] as const;

    for (const section of sections) {
      const sectionMap = pkg[section];
      if (!sectionMap || typeof sectionMap !== "object") continue;

      for (const [name, rawVersion] of Object.entries(
        sectionMap as Record<string, unknown>
      )) {
        if (seen.has(name)) continue;
        seen.add(name);
        // Strip range prefixes to get the installed version approximation
        const version =
          typeof rawVersion === "string"
            ? rawVersion.replace(/^[\^~>=<*| ]+/, "").split(" ")[0] || null
            : null;
        deps.push({ name, version, ecosystem: "npm" });
      }
    }

    return deps;
  }

  /**
   * Parse PyPI dependencies from pyproject.toml and/or requirements.txt content.
   * Normalizes package names to lowercase (PyPI convention).
   */
  private parsePypiDeps(
    pyprojectContent: string,
    requirementsContent: string | null
  ): RawDependency[] {
    const deps: RawDependency[] = [];
    const seen = new Set<string>();

    const addDep = (rawName: string, rawVersion: string | undefined) => {
      const name = rawName.toLowerCase().replace(/_/g, "-");
      if (seen.has(name)) return;
      seen.add(name);
      deps.push({
        name,
        version: rawVersion ?? null,
        ecosystem: "pypi",
      });
    };

    // Parse requirements.txt — format: package==1.0.0, package>=1.0, package
    if (requirementsContent) {
      for (const line of requirementsContent.split("\n")) {
        const clean = line.trim().split("#")[0].trim(); // strip inline comments
        if (!clean || clean.startsWith("-") || clean.startsWith("http://") || clean.startsWith("https://")) continue;
        const match = clean.match(/^([A-Za-z0-9_.-]+)\s*(?:[=><~!]+\s*([^\s,;]+))?/);
        if (match) addDep(match[1], match[2]);
      }
    }

    // Parse pyproject.toml [project] dependencies array
    // Format: dependencies = ["package>=1.0", "other==2.0"]
    if (pyprojectContent) {
      const depsBlock = /\[project\][\s\S]*?^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(
        pyprojectContent
      );
      if (depsBlock) {
        for (const rawLine of depsBlock[1].split("\n")) {
          const clean = rawLine.trim().replace(/^["']|["'],?\s*$/g, "");
          if (!clean) continue;
          const match = clean.match(/^([A-Za-z0-9_.-]+)\s*(?:[=><~!]+\s*([^\s,;]+))?/);
          if (match) addDep(match[1], match[2]);
        }
      }

      // Also parse [tool.poetry.dependencies]
      const poetryBlock = /\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\[|\z)/m.exec(
        pyprojectContent
      );
      if (poetryBlock) {
        for (const line of poetryBlock[1].split("\n")) {
          const match = line.match(/^([A-Za-z0-9_.-]+)\s*=\s*["']?([^"'\n]+)["']?/);
          if (match && match[1].toLowerCase() !== "python") {
            addDep(match[1], match[2].trim().replace(/^[\^~>=<*]+/, ""));
          }
        }
      }
    }

    return deps;
  }
}
