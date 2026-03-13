import { describe, it, expect, vi, beforeEach } from "vitest";
import { CrawlOrchestrator } from "./orchestrator.js";
import type { CrawlerSource, CrawlResult } from "./types.js";
import type { DiscoveredServer, DatabaseQueries } from "@mcp-sentinel/database";

// ─── Fixtures ─────────────────────────────────────────────────────────────────

function makeServer(overrides: Partial<DiscoveredServer> = {}): DiscoveredServer {
  return {
    name: "test-server",
    description: "A test MCP server",
    author: "testuser",
    github_url: "https://github.com/testuser/test-server",
    npm_package: null,
    pypi_package: null,
    category: null,
    language: "TypeScript",
    license: "MIT",
    source_name: "github",
    source_url: "https://github.com/testuser/test-server",
    external_id: "testuser/test-server",
    raw_metadata: {},
    ...overrides,
  };
}

function makeSource(
  name: string,
  servers: DiscoveredServer[],
  errors = 0
): CrawlerSource {
  return {
    name: name as CrawlerSource["name"],
    crawl: vi.fn().mockResolvedValue({
      source: name as CrawlerSource["name"],
      servers_found: servers.length,
      new_unique: servers.length,
      duplicates: 0,
      errors,
      elapsed_ms: 10,
      servers,
    } satisfies CrawlResult),
  };
}

function makeFailingSource(name: string): CrawlerSource {
  return {
    name: name as CrawlerSource["name"],
    crawl: vi.fn().mockRejectedValue(new Error("Network timeout")),
  };
}

function mockDb(upsertResult: string | Error = "uuid-1"): DatabaseQueries {
  return {
    upsertServer: vi.fn().mockImplementation(() => {
      if (upsertResult instanceof Error) return Promise.reject(upsertResult);
      return Promise.resolve(upsertResult);
    }),
  } as unknown as DatabaseQueries;
}

// ─── crawlAll: deduplication ───────────────────────────────────────────────────

describe("CrawlOrchestrator.crawlAll()", () => {
  it("deduplicates the same server across sources by github_url", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server]),
      makeSource("smithery", [
        { ...server, name: "repo-different-name", source_name: "smithery" },
      ]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.total_discovered).toBe(2);
    expect(stats.new_unique).toBe(1);
  });

  it("deduplicates by npm_package when no github_url", async () => {
    const base = makeServer({ github_url: null, npm_package: "@scope/my-mcp" });

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("npm", [{ ...base, source_name: "npm" }]),
      makeSource("pulsemcp", [{ ...base, name: "my-mcp-alt", source_name: "pulsemcp" }]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.new_unique).toBe(1);
  });

  it("deduplicates by pypi_package when no github or npm", async () => {
    const base = makeServer({
      github_url: null,
      npm_package: null,
      pypi_package: "my-mcp-server",
    });

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pypi", [{ ...base, source_name: "pypi" }]),
      makeSource("pulsemcp", [{ ...base, source_name: "pulsemcp" }]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.new_unique).toBe(1);
  });

  it("does NOT deduplicate servers with different identifiers", async () => {
    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [
        makeServer({ github_url: "https://github.com/user/server-a" }),
        makeServer({ github_url: "https://github.com/user/server-b" }),
      ]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.new_unique).toBe(2);
    expect(stats.total_discovered).toBe(2);
  });

  it("normalizes github_url for dedup (trailing slash, .git suffix)", async () => {
    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [
        makeServer({ github_url: "https://github.com/user/repo.git" }),
      ]),
      makeSource("smithery", [
        makeServer({ github_url: "https://github.com/user/repo/" }),
      ]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.new_unique).toBe(1);
  });

  it("falls back to name+author key when no package identifiers", async () => {
    const base = makeServer({ github_url: null, npm_package: null, pypi_package: null });

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [{ ...base, author: "alice" }]),
      makeSource("smithery", [{ ...base, author: "alice" }]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.new_unique).toBe(1);
  });

  it("counts per-source stats correctly", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server, makeServer({ github_url: "https://github.com/user/repo2" })]),
      makeSource("smithery", [server]), // duplicate of first
    ]);

    const stats = await orch.crawlAll();

    const pulsemcp = stats.per_source.find((s) => s.source === "pulsemcp")!;
    const smithery = stats.per_source.find((s) => s.source === "smithery")!;

    expect(pulsemcp.found).toBe(2);
    expect(pulsemcp.unique).toBe(2);
    expect(smithery.found).toBe(1);
    expect(smithery.unique).toBe(0); // already seen
  });

  it("computes data_quality counts correctly", async () => {
    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [
        makeServer({ github_url: "https://github.com/u/a", npm_package: "@u/a", description: "yes", category: "database" }),
        makeServer({ github_url: null, npm_package: null, description: null, category: null }),
      ]),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.data_quality.with_github_url).toBe(1);
    expect(stats.data_quality.with_npm_package).toBe(1);
    expect(stats.data_quality.with_description).toBe(1);
    expect(stats.data_quality.with_category).toBe(1);
  });

  it("handles a source that throws — records error, continues other sources", async () => {
    const orch = new CrawlOrchestrator(undefined, [
      makeFailingSource("pulsemcp"),
      makeSource("smithery", [makeServer()]),
    ]);

    const stats = await orch.crawlAll();

    const pulsemcp = stats.per_source.find((s) => s.source === "pulsemcp")!;
    expect(pulsemcp.errors).toBe(1);
    expect(pulsemcp.found).toBe(0);
    expect(stats.new_unique).toBe(1); // smithery server still counted
  });

  it("returns zero stats when all sources fail", async () => {
    const orch = new CrawlOrchestrator(undefined, [
      makeFailingSource("pulsemcp"),
      makeFailingSource("smithery"),
    ]);

    const stats = await orch.crawlAll();

    expect(stats.total_discovered).toBe(0);
    expect(stats.new_unique).toBe(0);
  });
});

// ─── crawlAndPersist ──────────────────────────────────────────────────────────

describe("CrawlOrchestrator.crawlAndPersist()", () => {
  it("calls upsertServer once per unique server", async () => {
    const shared = makeServer({ github_url: "https://github.com/user/repo" });
    const db = mockDb();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [shared, makeServer({ github_url: "https://github.com/user/repo2" })]),
      makeSource("smithery", [shared]), // duplicate
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(db.upsertServer).toHaveBeenCalledTimes(2);
    expect(stats.persisted).toBe(2);
    expect(stats.persist_errors).toBe(0);
  });

  it("counts persist_errors when upsertServer throws, continues remaining", async () => {
    const db = mockDb(new Error("DB connection refused"));

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [
        makeServer({ github_url: "https://github.com/user/a" }),
        makeServer({ github_url: "https://github.com/user/b" }),
      ]),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(stats.persist_errors).toBe(2);
    expect(stats.persisted).toBe(0);
  });

  it("returns extended stats with persisted and persist_errors fields", async () => {
    const db = mockDb();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [makeServer()]),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(stats).toHaveProperty("persisted");
    expect(stats).toHaveProperty("persist_errors");
    expect(stats).toHaveProperty("total_discovered");
    expect(stats).toHaveProperty("new_unique");
    expect(stats).toHaveProperty("per_source");
    expect(stats).toHaveProperty("data_quality");
  });

  it("persists zero servers when all sources fail", async () => {
    const db = mockDb();

    const orch = new CrawlOrchestrator(undefined, [
      makeFailingSource("pulsemcp"),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(db.upsertServer).not.toHaveBeenCalled();
    expect(stats.persisted).toBe(0);
    expect(stats.persist_errors).toBe(0);
  });

  it("does not call upsertServer for cross-source duplicates", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });
    const db = mockDb();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server]),
      makeSource("smithery", [server]),
      makeSource("npm",       [server]),
    ]);

    await orch.crawlAndPersist(db);

    // 3 sources, all same server → only 1 upsert
    expect(db.upsertServer).toHaveBeenCalledTimes(1);
  });
});
