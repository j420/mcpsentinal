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

/**
 * Create a mock DatabaseQueries for crawlAndPersist tests.
 *
 * upsertServerDedup is the method the orchestrator now calls.
 * It resolves { id, is_new } where is_new alternates true/false so tests can
 * verify both new_to_db and enriched_existing counters.
 *
 * Pass `error` to simulate a DB failure on every call.
 */
function mockDb(error?: Error): DatabaseQueries {
  let callCount = 0;
  return {
    upsertServerDedup: vi.fn().mockImplementation(() => {
      if (error) return Promise.reject(error);
      callCount++;
      // Alternate: first occurrence is new, subsequent occurrences are enrichments.
      // This matches real-world behavior where the first crawl creates the record.
      return Promise.resolve({ id: `uuid-${callCount}`, is_new: callCount === 1 });
    }),
    insertCrawlRun: vi.fn().mockResolvedValue("run-uuid-1"),
  } as unknown as DatabaseQueries;
}

/**
 * Mock where every upsertServerDedup call returns is_new=true (all new servers).
 */
function mockDbAllNew(): DatabaseQueries {
  let callCount = 0;
  return {
    upsertServerDedup: vi.fn().mockImplementation(() => {
      callCount++;
      return Promise.resolve({ id: `uuid-${callCount}`, is_new: true });
    }),
    insertCrawlRun: vi.fn().mockResolvedValue("run-uuid-1"),
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
    expect(pulsemcp.duplicates).toBe(0);
    expect(smithery.found).toBe(1);
    expect(smithery.unique).toBe(0); // already seen
    expect(smithery.duplicates).toBe(1);
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
  it("calls upsertServerDedup for every discovered server (including cross-source duplicates)", async () => {
    const shared = makeServer({ github_url: "https://github.com/user/repo" });
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [shared, makeServer({ github_url: "https://github.com/user/repo2" })]),
      makeSource("smithery", [shared]), // duplicate — still upserted so DB can enrich
    ]);

    const stats = await orch.crawlAndPersist(db);

    // 3 total server occurrences across sources → 3 upsert calls (DB enriches on subsequent hits)
    expect(db.upsertServerDedup).toHaveBeenCalledTimes(3);
    expect(stats.persisted).toBe(3);
    expect(stats.persist_errors).toBe(0);
    // in-memory dedup still reflects logical uniqueness
    expect(stats.new_unique).toBe(2);
  });

  it("tracks new_to_db and enriched_existing from upsertServerDedup results", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });
    let callCount = 0;
    const db = {
      // First call: new to DB. Second and third: enriching existing.
      upsertServerDedup: vi.fn().mockImplementation(() => {
        callCount++;
        return Promise.resolve({ id: `uuid-${callCount}`, is_new: callCount === 1 });
      }),
      insertCrawlRun: vi.fn().mockResolvedValue("run-uuid-1"),
    } as unknown as DatabaseQueries;

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server]),
      makeSource("smithery", [server]),
      makeSource("npm",       [server]),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(stats.new_to_db).toBe(1);
    expect(stats.enriched_existing).toBe(2);
    expect(stats.persisted).toBe(3);
  });

  it("counts persist_errors when upsertServerDedup throws, continues remaining", async () => {
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
    expect(stats.new_to_db).toBe(0);
    expect(stats.enriched_existing).toBe(0);
  });

  it("returns extended stats including new_to_db, enriched_existing, persisted, persist_errors", async () => {
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [makeServer()]),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(stats).toHaveProperty("persisted");
    expect(stats).toHaveProperty("persist_errors");
    expect(stats).toHaveProperty("new_to_db");
    expect(stats).toHaveProperty("enriched_existing");
    expect(stats).toHaveProperty("total_discovered");
    expect(stats).toHaveProperty("new_unique");
    expect(stats).toHaveProperty("per_source");
    expect(stats).toHaveProperty("data_quality");
  });

  it("persists zero servers when all sources fail", async () => {
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeFailingSource("pulsemcp"),
    ]);

    const stats = await orch.crawlAndPersist(db);

    expect(db.upsertServerDedup).not.toHaveBeenCalled();
    expect(stats.persisted).toBe(0);
    expect(stats.persist_errors).toBe(0);
    expect(stats.new_to_db).toBe(0);
    expect(stats.enriched_existing).toBe(0);
  });

  it("calls upsertServerDedup for every source occurrence to allow cross-source enrichment", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server]),
      makeSource("smithery", [server]),
      makeSource("npm",       [server]),
    ]);

    await orch.crawlAndPersist(db);

    // 3 source occurrences → 3 upsert calls; the dedup method handles enrichment internally
    expect(db.upsertServerDedup).toHaveBeenCalledTimes(3);
  });

  it("persists crawl run record via insertCrawlRun", async () => {
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [makeServer()]),
    ]);

    await orch.crawlAndPersist(db);

    expect(db.insertCrawlRun).toHaveBeenCalledTimes(1);
    const runArg = (db.insertCrawlRun as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(runArg).toMatchObject({
      total_discovered: 1,
      persist_errors: 0,
    });
    expect(runArg.started_at).toBeInstanceOf(Date);
    expect(runArg.completed_at).toBeInstanceOf(Date);
  });

  it("does not abort persist when insertCrawlRun throws", async () => {
    const db = {
      upsertServerDedup: vi.fn().mockResolvedValue({ id: "uuid-1", is_new: true }),
      insertCrawlRun: vi.fn().mockRejectedValue(new Error("DB unavailable")),
    } as unknown as DatabaseQueries;

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [makeServer()]),
    ]);

    const stats = await orch.crawlAndPersist(db);

    // Persist still completed even though insertCrawlRun failed
    expect(stats.persisted).toBe(1);
    expect(stats.new_to_db).toBe(1);
  });

  it("includes duplicates count in per_source stats", async () => {
    const server = makeServer({ github_url: "https://github.com/user/repo" });
    const db = mockDbAllNew();

    const orch = new CrawlOrchestrator(undefined, [
      makeSource("pulsemcp", [server, makeServer({ github_url: "https://github.com/user/repo2" })]),
      makeSource("smithery", [server]), // duplicate of first pulsemcp server
    ]);

    const stats = await orch.crawlAndPersist(db);

    const smithery = stats.per_source.find((s) => s.source === "smithery")!;
    expect(smithery.duplicates).toBe(1);
    expect(smithery.unique).toBe(0);
  });
});
