import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { ModelcontextprotocolRepoCrawler } from "./modelcontextprotocol-repo.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Build a base64-encoded GitHub Contents API file response */
function makeFileResponse(content: string) {
  const encoded = Buffer.from(content).toString("base64");
  // GitHub API wraps base64 in 76-char lines with \n
  const chunked = encoded.match(/.{1,76}/g)!.join("\n") + "\n";
  return { encoding: "base64", content: chunked };
}

/** Build a GitHub Contents API directory listing response */
function makeDirListing(
  dirs: string[],
  files: string[] = []
): Array<{ name: string; path: string; type: "dir" | "file"; sha: string; html_url: string; download_url: string | null }> {
  return [
    ...dirs.map((name) => ({
      name,
      path: `src/${name}`,
      type: "dir" as const,
      sha: `sha-${name}`,
      html_url: `https://github.com/modelcontextprotocol/servers/tree/main/src/${name}`,
      download_url: null as string | null,
    })),
    ...files.map((name) => ({
      name,
      path: `src/${name}`,
      type: "file" as const,
      sha: `sha-file-${name}`,
      html_url: `https://github.com/modelcontextprotocol/servers/blob/main/src/${name}`,
      download_url: `https://raw.githubusercontent.com/modelcontextprotocol/servers/main/src/${name}` as string | null,
    })),
  ];
}

function makePkgJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    name: "@modelcontextprotocol/server-filesystem",
    description: "Secure file operations with configurable access controls",
    version: "0.6.2",
    license: "MIT",
    keywords: ["mcp", "filesystem"],
    author: "Anthropic",
    ...overrides,
  });
}

function makePyproject(name = "mcp-server-git", description = "MCP server for Git"): string {
  return `[project]\nname = "${name}"\ndescription = "${description}"\nversion = "0.1.0"\n`;
}

/** Create a fetch mock that dispatches by URL */
function mockFetch(
  handlers: Record<string, { status: number; body: unknown }>
) {
  return vi.fn().mockImplementation((url: string) => {
    const handler = handlers[url];
    if (!handler) {
      return Promise.resolve({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ message: "Not Found" }),
      });
    }
    return Promise.resolve({
      ok: handler.status >= 200 && handler.status < 300,
      status: handler.status,
      json: () => Promise.resolve(handler.body),
    });
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("ModelcontextprotocolRepoCrawler", () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Happy path ──────────────────────────────────────────────────────────────

  it("TP1: discovers TypeScript server with package.json — populates all fields", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["filesystem"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/filesystem/package.json`]: {
        status: 200,
        body: makeFileResponse(
          makePkgJson({
            name: "@modelcontextprotocol/server-filesystem",
            description: "Secure file operations with configurable access controls",
            version: "0.6.2",
            license: "MIT",
            keywords: ["mcp", "filesystem"],
            author: "Anthropic",
          })
        ),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.source).toBe("official-registry");
    expect(result.servers_found).toBe(1);
    expect(result.errors).toBe(0);

    const server = result.servers[0];
    expect(server.name).toBe("@modelcontextprotocol/server-filesystem");
    expect(server.description).toBe("Secure file operations with configurable access controls");
    expect(server.npm_package).toBe("@modelcontextprotocol/server-filesystem");
    expect(server.language).toBe("TypeScript");
    expect(server.license).toBe("MIT");
    expect(server.author).toBe("Anthropic");
    expect(server.github_url).toBeNull(); // monorepo root must NOT be set
    expect(server.source_name).toBe("official-registry");
    expect(server.external_id).toBe("modelcontextprotocol/servers/src/filesystem");
    expect(server.raw_metadata.is_reference_implementation).toBe(true);
    expect(server.raw_metadata.src_path).toBe("src/filesystem");
    expect(server.raw_metadata.github_tree_url).toContain("/tree/main/src/filesystem");
    expect(server.raw_metadata.version).toBe("0.6.2");
    expect(server.raw_metadata.keywords).toEqual(["mcp", "filesystem"]);
    expect(server.category).toBe("filesystem");
  });

  it("TP2: discovers Python server with pyproject.toml — correct language and fields", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["git"]),
      },
      // no package.json → 404
      [`${API}/repos/modelcontextprotocol/servers/contents/src/git/package.json`]: {
        status: 404,
        body: { message: "Not Found" },
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/git/pyproject.toml`]: {
        status: 200,
        body: makeFileResponse(makePyproject("mcp-server-git", "MCP server for Git repository operations")),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(1);
    expect(result.errors).toBe(0);

    const server = result.servers[0];
    expect(server.name).toBe("mcp-server-git");
    expect(server.description).toBe("MCP server for Git repository operations");
    expect(server.language).toBe("Python");
    expect(server.npm_package).toBeNull();
    expect(server.source_name).toBe("official-registry");
    expect(server.external_id).toBe("modelcontextprotocol/servers/src/git");
    expect(server.raw_metadata.src_path).toBe("src/git");
  });

  it("TP3: discovers multiple servers in one crawl — returns all of them", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["filesystem", "postgres", "slack"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/filesystem/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@modelcontextprotocol/server-filesystem" })),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/postgres/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@modelcontextprotocol/server-postgres", description: "PostgreSQL integration" })),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/slack/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@modelcontextprotocol/server-slack", description: "Slack integration" })),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(3);
    expect(result.errors).toBe(0);
    const names = result.servers.map((s) => s.npm_package).sort();
    expect(names).toEqual([
      "@modelcontextprotocol/server-filesystem",
      "@modelcontextprotocol/server-postgres",
      "@modelcontextprotocol/server-slack",
    ]);
  });

  // ── Fallback behavior ───────────────────────────────────────────────────────

  it("TP4: falls back to dir name when neither package.json nor pyproject.toml exists", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["everything"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/everything/package.json`]: {
        status: 404,
        body: { message: "Not Found" },
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/everything/pyproject.toml`]: {
        status: 404,
        body: { message: "Not Found" },
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(1);
    const server = result.servers[0];
    expect(server.name).toBe("mcp-server-everything");
    expect(server.npm_package).toBeNull();
    expect(server.language).toBeNull();
    expect(server.description).toBeNull();
    expect(server.external_id).toBe("modelcontextprotocol/servers/src/everything");
  });

  it("TP5: author field from package.json object { name } is extracted correctly", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["puppeteer"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/puppeteer/package.json`]: {
        status: 200,
        body: makeFileResponse(
          JSON.stringify({ name: "@mcp/puppeteer", description: "Browser automation", author: { name: "MCP Team" } })
        ),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers[0].author).toBe("MCP Team");
  });

  // ── TN: non-directory entries are ignored ───────────────────────────────────

  it("TN1: files in src/ (README.md, etc.) are NOT included as servers", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(
          ["filesystem"], // dir → should become a server
          ["README.md", ".gitignore"] // files → must be skipped
        ),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/filesystem/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson()),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(1);
    expect(result.servers[0].name).toBe("@modelcontextprotocol/server-filesystem");
  });

  it("TN2: github_url is always null — never set to the monorepo root", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["filesystem", "postgres"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/filesystem/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@mcp/filesystem" })),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/postgres/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@mcp/postgres" })),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    // All servers must have null github_url to prevent dedup collision
    expect(result.servers.every((s) => s.github_url === null)).toBe(true);
  });

  // ── Error resilience ────────────────────────────────────────────────────────

  it("TP6: one directory fails → error counted, other servers still returned", async () => {
    const API = "https://api.github.com";
    // "badserver" package.json returns 500 — should be counted as error
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["filesystem", "badserver"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/filesystem/package.json`]: {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: "@mcp/filesystem" })),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/badserver/package.json`]: {
        status: 500,
        body: { message: "Internal Server Error" },
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.errors).toBe(1);
    expect(result.servers_found).toBe(1);
    expect(result.servers[0].name).toBe("@mcp/filesystem");
  });

  it("TN3: fatal failure on src/ listing — returns 0 servers and 1 error", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 503,
        body: { message: "Service Unavailable" },
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(0);
    expect(result.errors).toBe(1);
    expect(result.servers).toHaveLength(0);
  });

  it("TN4: empty src/ directory — returns 0 servers and 0 errors", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: [],
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(0);
    expect(result.errors).toBe(0);
  });

  // ── Authentication ─────────────────────────────────────────────────────────

  it("TP7: GITHUB_TOKEN is passed as Authorization header", async () => {
    const API = "https://api.github.com";
    const spy = vi.fn().mockImplementation((url: string, opts?: RequestInit) => {
      if (url === `${API}/repos/modelcontextprotocol/servers/contents/src`) {
        // Verify auth header was set
        const auth = (opts?.headers as Record<string, string>)?.Authorization;
        expect(auth).toBe("Bearer test-token-123");
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(makeDirListing([])),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    });
    global.fetch = spy;

    const crawler = new ModelcontextprotocolRepoCrawler("test-token-123");
    await crawler.crawl();

    expect(spy).toHaveBeenCalled();
  });

  it("TN5: no token — Authorization header is absent", async () => {
    const API = "https://api.github.com";
    const spy = vi.fn().mockImplementation((url: string, opts?: RequestInit) => {
      if (url === `${API}/repos/modelcontextprotocol/servers/contents/src`) {
        const auth = (opts?.headers as Record<string, string>)?.Authorization;
        expect(auth).toBeUndefined();
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(makeDirListing([])),
        });
      }
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve([]) });
    });
    global.fetch = spy;

    const crawler = new ModelcontextprotocolRepoCrawler(undefined);
    await crawler.crawl();

    expect(spy).toHaveBeenCalled();
  });

  // ── CrawlResult contract ───────────────────────────────────────────────────

  it("result always has all required CrawlResult fields", async () => {
    const API = "https://api.github.com";
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing([]),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result).toHaveProperty("source", "official-registry");
    expect(result).toHaveProperty("servers_found");
    expect(result).toHaveProperty("new_unique");
    expect(result).toHaveProperty("duplicates", 0);
    expect(result).toHaveProperty("errors");
    expect(result).toHaveProperty("elapsed_ms");
    expect(result).toHaveProperty("servers");
    expect(result.elapsed_ms).toBeGreaterThanOrEqual(0);
  });

  // ── Category inference ─────────────────────────────────────────────────────

  it("TP8: category is correctly inferred from directory name", async () => {
    const API = "https://api.github.com";
    const dirs = ["postgres", "filesystem", "puppeteer", "slack", "git"];
    const responses: Record<string, { status: number; body: unknown }> = {
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(dirs),
      },
    };
    for (const dir of dirs) {
      responses[`${API}/repos/modelcontextprotocol/servers/contents/src/${dir}/package.json`] = {
        status: 200,
        body: makeFileResponse(makePkgJson({ name: `@mcp/${dir}`, description: "" })),
      };
    }
    global.fetch = mockFetch(responses);

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    const byDir = Object.fromEntries(
      result.servers.map((s) => [
        (s.raw_metadata as Record<string, unknown>).dir_name,
        s.category,
      ])
    );

    expect(byDir["postgres"]).toBe("database");
    expect(byDir["filesystem"]).toBe("filesystem");
    expect(byDir["puppeteer"]).toBe("browser-web");
    expect(byDir["slack"]).toBe("api-integration");
    expect(byDir["git"]).toBe("dev-tools");
  });

  // ── Pyproject.toml scoping ─────────────────────────────────────────────────

  it("TP9: pyproject.toml [project] section is scoped correctly — ignores tool.poetry name", async () => {
    const API = "https://api.github.com";
    const toml = `
[tool.poetry]
name = "wrong-name"
description = "wrong description"

[project]
name = "correct-name"
description = "correct description"
version = "1.0.0"
`;
    global.fetch = mockFetch({
      [`${API}/repos/modelcontextprotocol/servers/contents/src`]: {
        status: 200,
        body: makeDirListing(["myserver"]),
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/myserver/package.json`]: {
        status: 404,
        body: {},
      },
      [`${API}/repos/modelcontextprotocol/servers/contents/src/myserver/pyproject.toml`]: {
        status: 200,
        body: makeFileResponse(toml),
      },
    });

    const crawler = new ModelcontextprotocolRepoCrawler("tok");
    const result = await crawler.crawl();

    expect(result.servers[0].name).toBe("correct-name");
    expect(result.servers[0].description).toBe("correct description");
  });
});
