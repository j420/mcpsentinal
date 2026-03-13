import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { McpRegistryCrawler } from "./mcpregistry.js";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeRegistryEntry(overrides: {
  name?: string;
  /** Pass null to omit title from the server object (tests fallback to server.name) */
  title?: string | null;
  description?: string;
  version?: string;
  websiteUrl?: string;
  repositoryUrl?: string;
  /** Pass null to omit npm package from packages array */
  npmIdentifier?: string | null;
  pypiIdentifier?: string;
  isLatest?: boolean;
  status?: string;
  hasMeta?: boolean;
}) {
  const {
    name = "io.example/test-server",
    title = "Test Server",
    description = "A test MCP server",
    version = "1.0.0",
    websiteUrl,
    repositoryUrl = "https://github.com/example/test-server",
    npmIdentifier = "@example/test-server",
    pypiIdentifier,
    isLatest = true,
    status = "active",
    hasMeta = true,
  } = overrides;

  // Build server object — omit title when caller explicitly passes null
  const serverObj: Record<string, unknown> = { name, description, version, websiteUrl };
  if (title !== null) serverObj.title = title;
  if (repositoryUrl) serverObj.repository = { url: repositoryUrl, source: "github" };
  serverObj.packages = [
    // null means caller wants NO npm package; undefined means "use default"
    ...(npmIdentifier != null
      ? [{ registryType: "npm", identifier: npmIdentifier, version }]
      : []),
    ...(pypiIdentifier
      ? [{ registryType: "pypi", identifier: pypiIdentifier, version }]
      : []),
  ];

  return {
    server: serverObj,
    _meta: hasMeta
      ? {
          "io.modelcontextprotocol.registry/official": {
            status,
            isLatest,
            publishedAt: "2025-01-15T10:00:00Z",
            updatedAt: "2025-06-01T12:00:00Z",
          },
        }
      : {},
  };
}

function mockFetch(pages: Array<{ status: number; body: unknown }>) {
  let callCount = 0;
  return vi.fn().mockImplementation(() => {
    const page = pages[callCount] ?? pages[pages.length - 1];
    callCount++;
    return Promise.resolve({
      ok: page.status >= 200 && page.status < 300,
      status: page.status,
      json: () => Promise.resolve(page.body),
    });
  });
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("McpRegistryCrawler", () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  // ── Happy path ──────────────────────────────────────────────────────────────

  it("TP1: discovers a server with all fields populated", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [makeRegistryEntry({ name: "io.exa/exa", title: "Exa Search", description: "Web search API" })],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.source).toBe("official-registry");
    expect(result.servers_found).toBe(1);
    expect(result.errors).toBe(0);

    const server = result.servers[0];
    expect(server.name).toBe("Exa Search");
    expect(server.description).toBe("Web search API");
    expect(server.npm_package).toBe("@example/test-server");
    expect(server.github_url).toBe("https://github.com/example/test-server");
    expect(server.source_name).toBe("official-registry");
    expect(server.external_id).toBe("io.exa/exa");
    expect((server.raw_metadata as Record<string, unknown>).status).toBe("active");
  });

  it("TP2: extracts PyPI package when present and no npm package", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({
              name: "io.example/py-server",
              title: "Python Server",
              npmIdentifier: null,
              pypiIdentifier: "mcp-server-python",
            }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers[0].npm_package).toBeNull();
    expect(result.servers[0].pypi_package).toBe("mcp-server-python");
  });

  it("TP3: paginates through multiple pages until no nextCursor", async () => {
    const entry1 = makeRegistryEntry({ name: "io.a/server-a", title: "Server A" });
    const entry2 = makeRegistryEntry({ name: "io.b/server-b", title: "Server B" });

    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [entry1],
          metadata: { nextCursor: "cursor-page2", count: 1 },
        },
      },
      {
        status: 200,
        body: {
          servers: [entry2],
          metadata: { count: 1 }, // no nextCursor → stop
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(2);
    const names = result.servers.map((s) => s.external_id).sort();
    expect(names).toEqual(["io.a/server-a", "io.b/server-b"]);
  });

  it("TP4: uses server.title as the name when available, falls back to server.name", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({ name: "io.x/no-title", title: null }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    // title is undefined — should fall back to server.name
    expect(result.servers[0].name).toBe("io.x/no-title");
  });

  // ── Filtering ───────────────────────────────────────────────────────────────

  it("TN1: non-latest entries (isLatest: false) are skipped", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({ name: "io.x/old-version", isLatest: false }),
            makeRegistryEntry({ name: "io.x/new-version", isLatest: true }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(1);
    expect(result.servers[0].external_id).toBe("io.x/new-version");
  });

  it("TN2: entries missing _meta entirely are skipped without throwing", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({ name: "io.legit/server", hasMeta: true, isLatest: true }),
            makeRegistryEntry({ name: "io.no-meta/server", hasMeta: false }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    // Only the server with valid _meta should appear
    expect(result.servers_found).toBe(1);
    expect(result.servers[0].external_id).toBe("io.legit/server");
    expect(result.errors).toBe(0);
  });

  // ── GitHub URL normalization ────────────────────────────────────────────────

  it("TP5: github_url is normalized — .git suffix and trailing slash stripped", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({
              name: "io.x/server",
              repositoryUrl: "https://github.com/org/repo.git",
            }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers[0].github_url).toBe("https://github.com/org/repo");
  });

  it("TN3: non-GitHub repository URL — github_url is null", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({
              name: "io.x/server",
              repositoryUrl: "https://gitlab.com/org/repo",
            }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers[0].github_url).toBeNull();
  });

  // ── Error handling ──────────────────────────────────────────────────────────

  it("TP6: API returns non-ok status — increments errors and stops pagination", async () => {
    global.fetch = mockFetch([{ status: 503, body: { message: "Unavailable" } }]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(0);
    expect(result.errors).toBe(1);
  });

  it("TN4: fetch throws a network error — returns 0 servers and 1 error", async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error("Network timeout"));

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers_found).toBe(0);
    expect(result.errors).toBe(1);
  });

  // ── CrawlResult contract ───────────────────────────────────────────────────

  it("result always has all required CrawlResult fields", async () => {
    global.fetch = mockFetch([
      { status: 200, body: { servers: [], metadata: {} } },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result).toHaveProperty("source", "official-registry");
    expect(result).toHaveProperty("servers_found", 0);
    expect(result).toHaveProperty("new_unique", 0);
    expect(result).toHaveProperty("duplicates", 0);
    expect(result).toHaveProperty("errors", 0);
    expect(result).toHaveProperty("elapsed_ms");
    expect(result).toHaveProperty("servers");
    expect(result.elapsed_ms).toBeGreaterThanOrEqual(0);
  });

  // ── Author extraction ──────────────────────────────────────────────────────

  it("TP7: author is extracted from qualified server name namespace (ai.exa/exa → exa)", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [makeRegistryEntry({ name: "ai.exa/exa", title: "Exa" })],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect(result.servers[0].author).toBe("exa");
  });

  it("TP8: server with websiteUrl stores has_remote: true in raw_metadata", async () => {
    global.fetch = mockFetch([
      {
        status: 200,
        body: {
          servers: [
            makeRegistryEntry({
              name: "io.x/remote",
              websiteUrl: "https://example.com/mcp",
            }),
          ],
          metadata: {},
        },
      },
    ]);

    const crawler = new McpRegistryCrawler();
    const result = await crawler.crawl();

    expect((result.servers[0].raw_metadata as Record<string, unknown>).has_remote).toBe(true);
  });
});
