/**
 * Scanner package tests
 *
 * Coverage:
 *   1. SourceFetcher — URL parsing and dep parsing (via mocked fetch)
 *   2. DependencyAuditor — empty-array fast-path and enrichment (via mocked fetch)
 *   3. Fixture validation — every vulnerable pattern the rules detect is present
 *      in fixtures/vulnerable-server.ts (guards against regressions)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SourceFetcher } from "./fetcher.js";
import { DependencyAuditor } from "./auditor.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const FIXTURE_PATH = path.resolve(__dirname, "fixtures/vulnerable-server.ts");
const fixtureSource = readFileSync(FIXTURE_PATH, "utf-8");

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Build a minimal Response-like object for vi.stubGlobal('fetch', ...) */
function mockResponse(body: unknown, status = 200): Response {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ── 1. SourceFetcher ──────────────────────────────────────────────────────────

describe("SourceFetcher", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("fetchFromGitHub — invalid inputs", () => {
    it("returns error for a non-GitHub URL without making any network calls", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://gitlab.com/owner/repo");

      expect(result.source_code).toBeNull();
      expect(result.error).toMatch(/Cannot parse/i);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("returns error for a malformed URL without making any network calls", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("not-a-url-at-all");

      expect(result.source_code).toBeNull();
      expect(result.error).toBeTruthy();
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it("returns error for a GitHub URL with no repo path segment", async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal("fetch", fetchSpy);

      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/only-owner");

      expect(result.error).toBeTruthy();
      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe("fetchFromGitHub — npm project (mocked fetch)", () => {
    const PACKAGE_JSON = {
      name: "test-mcp-server",
      main: "src/index.ts",
      dependencies: {
        express: "^4.18.2",
        lodash: "4.17.21",
      },
      devDependencies: {
        typescript: "^5.0.0",
        vitest: "^2.0.0",
      },
    };

    const SOURCE_CONTENT = `export const hello = "world"; // src/index.ts`;

    beforeEach(() => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const u = url.toString();
          // GitHub API — default branch
          if (u.includes("api.github.com/repos")) {
            return mockResponse({ default_branch: "main" });
          }
          // Raw package.json
          if (u.endsWith("/package.json")) {
            return mockResponse(JSON.stringify(PACKAGE_JSON));
          }
          // main entry (src/index.ts)
          if (u.endsWith("/src/index.ts")) {
            return mockResponse(SOURCE_CONTENT);
          }
          // Everything else — 404
          return mockResponse("Not Found", 404);
        })
      );
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("returns source code when entry file is found", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");

      expect(result.error).toBeNull();
      expect(result.source_code).not.toBeNull();
      expect(result.source_code).toContain(SOURCE_CONTENT);
    });

    it("parses npm dependencies from package.json", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");

      // Should include both dependencies and devDependencies
      const names = result.raw_dependencies.map((d) => d.name);
      expect(names).toContain("express");
      expect(names).toContain("lodash");
      expect(names).toContain("typescript");
    });

    it("strips semver range prefixes from dependency versions", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");

      const express = result.raw_dependencies.find((d) => d.name === "express");
      const lodash = result.raw_dependencies.find((d) => d.name === "lodash");

      // ^ prefix stripped
      expect(express?.version).toBe("4.18.2");
      // no prefix
      expect(lodash?.version).toBe("4.17.21");
    });

    it("marks all npm dependencies with ecosystem=npm", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");

      for (const dep of result.raw_dependencies) {
        expect(dep.ecosystem).toBe("npm");
      }
    });

    it("includes package.json in source for C5 secret scanning", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");

      // package.json should always be included so C5 can scan it for embedded tokens
      expect(result.files_fetched).toContain("package.json");
    });

    it("handles .git suffix in GitHub URL", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub(
        "https://github.com/owner/test-repo.git"
      );
      expect(result.error).toBeNull();
    });

    it("gracefully handles missing source files (all 404) — returns null source_code", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const u = url.toString();
          if (u.includes("api.github.com/repos")) {
            return mockResponse({ default_branch: "main" });
          }
          // Everything else 404 — no source, no package.json
          return mockResponse("Not Found", 404);
        })
      );

      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/empty-repo");

      expect(result.error).toBeNull();
      expect(result.source_code).toBeNull();
      expect(result.raw_dependencies).toHaveLength(0);
      expect(result.files_fetched).toHaveLength(0);
    });

    it("degrades gracefully when GitHub API returns non-200 for default branch", async () => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const u = url.toString();
          if (u.includes("api.github.com/repos")) {
            return mockResponse("Forbidden", 403);
          }
          if (u.endsWith("/package.json")) {
            return mockResponse(JSON.stringify(PACKAGE_JSON));
          }
          if (u.endsWith("/src/index.ts")) {
            return mockResponse(SOURCE_CONTENT);
          }
          return mockResponse("Not Found", 404);
        })
      );

      const fetcher = new SourceFetcher();
      // Should fall back to 'main' branch and still work
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/test-repo");
      expect(result.error).toBeNull();
    });
  });

  describe("fetchFromGitHub — PyPI project (mocked fetch)", () => {
    const REQUIREMENTS_TXT = [
      "mcp>=1.0.0",
      "fastapi==0.110.0",
      "pydantic>=2.0",
      "# comment line",
      "httpx~=0.27.0",
    ].join("\n");

    const PYPROJECT_TOML = `
[project]
name = "test-mcp"
version = "0.1.0"
dependencies = [
    "mcp>=1.0.0",
    "aiohttp>=3.9",
]
`;

    beforeEach(() => {
      vi.stubGlobal(
        "fetch",
        vi.fn(async (url: string | URL | Request) => {
          const u = url.toString();
          if (u.includes("api.github.com/repos")) {
            return mockResponse({ default_branch: "main" });
          }
          // No package.json → Python project
          if (u.endsWith("/package.json")) return mockResponse("Not Found", 404);
          if (u.endsWith("/pyproject.toml")) return mockResponse(PYPROJECT_TOML);
          if (u.endsWith("/requirements.txt")) return mockResponse(REQUIREMENTS_TXT);
          if (u.endsWith("/server.py")) return mockResponse('print("hello")');
          return mockResponse("Not Found", 404);
        })
      );
    });

    afterEach(() => {
      vi.unstubAllGlobals();
    });

    it("parses requirements.txt dependencies", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/py-server");

      const names = result.raw_dependencies.map((d) => d.name);
      expect(names).toContain("mcp");
      expect(names).toContain("fastapi");
      expect(names).toContain("pydantic");
      expect(names).toContain("httpx");
    });

    it("strips version specifiers from requirements.txt", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/py-server");

      const fastapi = result.raw_dependencies.find((d) => d.name === "fastapi");
      expect(fastapi?.version).toBe("0.110.0");
    });

    it("deduplicates deps that appear in both pyproject.toml and requirements.txt", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/py-server");

      const mcpEntries = result.raw_dependencies.filter((d) => d.name === "mcp");
      expect(mcpEntries).toHaveLength(1);
    });

    it("marks PyPI dependencies with ecosystem=pypi", async () => {
      const fetcher = new SourceFetcher();
      const result = await fetcher.fetchFromGitHub("https://github.com/owner/py-server");

      for (const dep of result.raw_dependencies) {
        expect(dep.ecosystem).toBe("pypi");
      }
    });
  });
});

// ── 2. DependencyAuditor ──────────────────────────────────────────────────────

describe("DependencyAuditor", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns empty array immediately for empty input — no network calls made", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([]);

    expect(result).toHaveLength(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("enriches a dep with known CVE from OSV batch response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        mockResponse({
          results: [
            {
              vulns: [
                {
                  id: "GHSA-abc-123",
                  aliases: ["CVE-2023-12345"],
                },
              ],
            },
          ],
        })
      )
    );

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([
      { name: "lodash", version: "4.17.20", ecosystem: "npm" },
    ]);

    expect(result).toHaveLength(1);
    expect(result[0]?.has_known_cve).toBe(true);
    expect(result[0]?.cve_ids).toContain("CVE-2023-12345");
  });

  it("returns has_known_cve=false when OSV reports no vulns", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => mockResponse({ results: [{ vulns: [] }] }))
    );

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([
      { name: "safe-package", version: "1.0.0", ecosystem: "npm" },
    ]);

    expect(result[0]?.has_known_cve).toBe(false);
    expect(result[0]?.cve_ids).toHaveLength(0);
  });

  it("extracts only CVE-prefixed aliases, ignoring other OSV IDs", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        mockResponse({
          results: [
            {
              vulns: [
                {
                  id: "GHSA-xxxx-yyyy-zzzz",
                  aliases: ["CVE-2024-99999", "GHSA-other-id", "CVE-2024-88888"],
                },
              ],
            },
          ],
        })
      )
    );

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([
      { name: "vuln-pkg", version: "2.0.0", ecosystem: "pypi" },
    ]);

    expect(result[0]?.cve_ids).toContain("CVE-2024-99999");
    expect(result[0]?.cve_ids).toContain("CVE-2024-88888");
    expect(result[0]?.cve_ids).not.toContain("GHSA-xxxx-yyyy-zzzz");
    expect(result[0]?.cve_ids).not.toContain("GHSA-other-id");
  });

  it("falls back to individual queries when batch API fails, returning no-vuln records", async () => {
    // Batch fails with 500, individual also fails — should still return a result per dep
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => mockResponse("Internal Server Error", 500))
    );

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([
      { name: "some-pkg", version: "1.0.0", ecosystem: "npm" },
      { name: "other-pkg", version: "2.0.0", ecosystem: "npm" },
    ]);

    // Still returns one result per dep — never loses a dep on audit failure
    expect(result).toHaveLength(2);
    for (const dep of result) {
      expect(dep.has_known_cve).toBe(false);
      expect(dep.cve_ids).toHaveLength(0);
    }
  });

  it("preserves dep name, version, and ecosystem through enrichment", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => mockResponse({ results: [{ vulns: [] }] }))
    );

    const auditor = new DependencyAuditor();
    const result = await auditor.audit([
      { name: "my-lib", version: "3.2.1", ecosystem: "pypi" },
    ]);

    expect(result[0]?.name).toBe("my-lib");
    expect(result[0]?.version).toBe("3.2.1");
    expect(result[0]?.ecosystem).toBe("pypi");
  });
});

// ── 3. Fixture Pattern Validation ─────────────────────────────────────────────
//
// These tests assert that fixtures/vulnerable-server.ts contains the exact
// source patterns that each detection rule's regex is designed to match.
// If a fixture pattern is removed or changed, the corresponding rule's
// true-positive test case breaks here — catching regressions before CI.

describe("Fixture: vulnerable-server.ts pattern validation", () => {
  it("C1 — exec( with user input", () => {
    expect(fixtureSource).toMatch(/exec\s*\(/);
  });

  it("C1 — execSync( with user input", () => {
    expect(fixtureSource).toMatch(/execSync\s*\(/);
  });

  it("C2 — path traversal (../../../)", () => {
    expect(fixtureSource).toMatch(/\.\.\//);
  });

  it("C4 — SQL injection via template literal", () => {
    // Matches: `SELECT * FROM users WHERE id = '${userId}'`
    expect(fixtureSource).toMatch(/`SELECT.*\$\{/s);
  });

  it("C5 — hardcoded OpenAI key (sk-proj-)", () => {
    expect(fixtureSource).toMatch(/sk-proj-/);
  });

  it("C5 — hardcoded GitHub PAT (ghp_)", () => {
    expect(fixtureSource).toMatch(/ghp_/);
  });

  it("C5 — hardcoded AWS key ID (AKIA)", () => {
    expect(fixtureSource).toMatch(/AKIA[A-Z0-9]{16}/);
  });

  it("C5 — hardcoded Stripe live key (sk_live_)", () => {
    expect(fixtureSource).toMatch(/sk_live_/);
  });

  it("C5 — hardcoded Anthropic key (sk-ant-)", () => {
    expect(fixtureSource).toMatch(/sk-ant-/);
  });

  it("C7 — wildcard CORS header (Access-Control-Allow-Origin + *)", () => {
    expect(fixtureSource).toMatch(/Access-Control-Allow-Origin/);
    expect(fixtureSource).toMatch(/"[*]"/);
  });

  it("C8 — listens on 0.0.0.0", () => {
    expect(fixtureSource).toMatch(/0\.0\.0\.0/);
  });

  it("C9 — excessive filesystem scope (reads from /)", () => {
    // readFileSync(`/${path}`) — root-level access
    expect(fixtureSource).toMatch(/readFileSync\s*\(\s*`\/\$\{/);
  });

  it("C10 — prototype pollution via __proto__", () => {
    expect(fixtureSource).toMatch(/__proto__/);
  });

  it("C14 — JWT algorithm confusion: allowlist includes 'none'", () => {
    expect(fixtureSource).toMatch(/["']none["']/);
  });

  it("C14 — ignoreExpiration pattern present", () => {
    expect(fixtureSource).toMatch(/ignoreExpiration\s*=\s*true/);
  });

  it("C15 — timing-unsafe === comparison on key/token", () => {
    // provided === stored  (timing attack)
    expect(fixtureSource).toMatch(/provided\s*===\s*stored/);
  });

  it("C16 — dynamic eval() with user input", () => {
    expect(fixtureSource).toMatch(/\beval\s*\(/);
  });
});
