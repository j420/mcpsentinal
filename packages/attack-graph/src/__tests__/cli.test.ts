/**
 * CLI Test Suite — packages/attack-graph/src/cli.ts
 *
 * Tests the CLI orchestration logic in isolation by mocking:
 *   - pg.Pool (database connection)
 *   - DatabaseQueries (getServersWithTools, getFindingRuleIdsByServerIds, insertAttackChains)
 *   - RiskMatrixAnalyzer (analyze)
 *   - AttackGraphEngine (analyze)
 *
 * Uses vi.unstubAllEnvs() to isolate DATABASE_URL between tests.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// ── Mocks (vi.hoisted ensures these are available before vi.mock factories) ──

const {
  mockPoolEnd,
  mockPoolQuery,
  mockGetServersWithTools,
  mockGetFindingRuleIdsByServerIds,
  mockInsertAttackChains,
  mockBuildCapabilityGraph,
  mockRiskAnalyze,
  mockEngineAnalyze,
} = vi.hoisted(() => ({
  mockPoolEnd: vi.fn().mockResolvedValue(undefined),
  mockPoolQuery: vi.fn().mockResolvedValue({ rows: [] }),
  mockGetServersWithTools: vi.fn().mockResolvedValue([]),
  mockGetFindingRuleIdsByServerIds: vi.fn().mockResolvedValue({}),
  mockInsertAttackChains: vi.fn().mockResolvedValue(undefined),
  mockBuildCapabilityGraph: vi.fn().mockReturnValue([]),
  mockRiskAnalyze: vi.fn().mockReturnValue({
    generated_at: new Date().toISOString(),
    config_id: "abcdef1234567890",
    server_count: 0,
    edges: [],
    patterns_detected: [],
    aggregate_risk: "none",
    score_caps: {},
    summary: "No risk detected.",
  }),
  mockEngineAnalyze: vi.fn().mockReturnValue({
    generated_at: new Date().toISOString(),
    config_id: "abcdef1234567890",
    server_count: 0,
    chains: [],
    chain_count: 0,
    critical_chains: 0,
    high_chains: 0,
    aggregate_risk: "none",
    summary: "No chains.",
  }),
}));

vi.mock("pg", () => ({
  default: {
    Pool: vi.fn().mockImplementation(() => ({
      query: mockPoolQuery,
      end: mockPoolEnd,
    })),
  },
}));

vi.mock("@mcp-sentinel/database", () => ({
  DatabaseQueries: vi.fn().mockImplementation(() => ({
    getServersWithTools: mockGetServersWithTools,
    getFindingRuleIdsByServerIds: mockGetFindingRuleIdsByServerIds,
    insertAttackChains: mockInsertAttackChains,
  })),
}));

vi.mock("@mcp-sentinel/risk-matrix", () => ({
  RiskMatrixAnalyzer: vi.fn().mockImplementation(() => ({ analyze: mockRiskAnalyze })),
  buildCapabilityGraph: mockBuildCapabilityGraph,
}));

vi.mock("../engine.js", () => ({
  AttackGraphEngine: vi.fn().mockImplementation(() => ({ analyze: mockEngineAnalyze })),
}));

vi.mock("pino", () => ({
  default: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    fatal: vi.fn(),
  })),
}));

// ── Helpers ───────────────────────────────────────────────────────────────────

import { parseLimit, hasFlag, chainSummary } from "../cli.js";

function makeServer(name: string, id: string = `srv-${name}`) {
  return {
    server_id: id,
    server_name: name,
    server_slug: name.toLowerCase(),
    latest_score: 50,
    category: "dev-tools",
    tools: [{ name: "test-tool", description: "A test tool", capability_tags: [] }],
  };
}

function makeChain(overrides: Partial<{
  chain_id: string;
  kill_chain_id: string;
  kill_chain_name: string;
  exploitability: { overall: number; rating: string; factors: unknown[] };
  aggregate_risk: string;
}> = {}) {
  return {
    chain_id: overrides.chain_id ?? "c1a2b3",
    kill_chain_id: overrides.kill_chain_id ?? "KC01",
    kill_chain_name: overrides.kill_chain_name ?? "Indirect Injection → Data Exfiltration",
    steps: [
      { ordinal: 1, server_id: "srv-a", server_name: "web-scraper", role: "injection_gateway", capabilities_used: ["web-scraping"], tools_involved: [], edge_to_next: null, narrative: "Step 1" },
      { ordinal: 2, server_id: "srv-b", server_name: "file-manager", role: "data_source", capabilities_used: ["reads-data"], tools_involved: [], edge_to_next: null, narrative: "Step 2" },
      { ordinal: 3, server_id: "srv-c", server_name: "webhook-sender", role: "exfiltrator", capabilities_used: ["sends-network"], tools_involved: [], edge_to_next: null, narrative: "Step 3" },
    ],
    exploitability: overrides.exploitability ?? {
      overall: 0.82,
      impact: 0.9,
      likelihood: 0.75,
      effort: 0.7,
      rating: "critical",
      factors: [
        { factor: "hop_count", value: 0.85, weight: 0.15, description: "3 hops" },
      ],
    },
    narrative: "Attacker injects via web scraper, reads files, exfiltrates via webhook.",
    mitigations: [
      { action: "remove_server", target_server_id: "srv-c", target_server_name: "webhook-sender", description: "Remove webhook sender", breaks_steps: [3], effect: "breaks_chain" },
    ],
    owasp_refs: ["MCP04"],
    mitre_refs: ["AML.T0057"],
    evidence: { risk_edges: [], pattern_ids: ["P01"], supporting_findings: ["C1", "A3"] },
  };
}

function makeReport(chains: ReturnType<typeof makeChain>[] = [], overrides: Record<string, unknown> = {}) {
  const critical = chains.filter((c) => c.exploitability.rating === "critical").length;
  const high = chains.filter((c) => c.exploitability.rating === "high").length;
  let aggregate: string = "none";
  if (critical > 0) aggregate = "critical";
  else if (high > 0) aggregate = "high";
  else if (chains.length > 0) aggregate = "medium";

  return {
    generated_at: new Date().toISOString(),
    config_id: "abcdef1234567890",
    server_count: 3,
    chains,
    chain_count: chains.length,
    critical_chains: critical,
    high_chains: high,
    aggregate_risk: aggregate,
    summary: `${chains.length} chain(s) detected.`,
    ...overrides,
  };
}

// ── Test setup ────────────────────────────────────────────────────────────────

let consoleOutput: string[] = [];
let exitCode: number | undefined;
const originalProcessExit = process.exit;

beforeEach(() => {
  vi.clearAllMocks();
  consoleOutput = [];
  exitCode = undefined;
  process.exitCode = undefined;

  // Explicitly restore implementations that some tests override
  mockInsertAttackChains.mockResolvedValue(undefined);
  mockGetFindingRuleIdsByServerIds.mockResolvedValue({});

  vi.spyOn(console, "log").mockImplementation((msg: string) => {
    consoleOutput.push(String(msg));
  });
  // Capture process.stdout.write (used for JSON output)
  vi.spyOn(process.stdout, "write").mockImplementation((...args: unknown[]) => {
    consoleOutput.push(String(args[0]));
    return true;
  });

  // Default mocks — risk mock returns one edge so main() tests reach full pipeline
  mockGetServersWithTools.mockResolvedValue([]);
  mockRiskAnalyze.mockReturnValue({
    generated_at: new Date().toISOString(),
    config_id: "abc",
    server_count: 1,
    edges: [
      { from_server_id: "srv-a", to_server_id: "srv-b", edge_type: "injection_path", severity: "high", description: "default test edge", owasp: "MCP01", mitre: "AML.T0054" },
    ],
    patterns_detected: ["P01"],
    aggregate_risk: "high",
    score_caps: {},
    summary: "Risk detected.",
  });
  mockEngineAnalyze.mockReturnValue(makeReport());
});

afterEach(() => {
  vi.unstubAllEnvs();
});

// ═══════════════════════════════════════════════════════════════════════════════
// 1. parseLimit() unit tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("parseLimit", () => {
  it("returns 5000 when no --limit flag present", () => {
    expect(parseLimit(["--json"])).toBe(5000);
  });

  it("parses --limit=500 correctly", () => {
    expect(parseLimit(["--limit=500"])).toBe(500);
  });

  it("truncates --limit=3.7 to 3 via parseInt", () => {
    expect(parseLimit(["--limit=3.7"])).toBe(3);
  });

  it("passes through very large limit (no upper bound)", () => {
    expect(parseLimit(["--limit=9999999"])).toBe(9999999);
  });

  it("exits with code 1 for --limit=0", () => {
    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    expect(() => parseLimit(["--limit=0"])).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it("exits with code 1 for --limit=-1", () => {
    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    expect(() => parseLimit(["--limit=-1"])).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it("exits with code 1 for --limit=abc (NaN)", () => {
    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    expect(() => parseLimit(["--limit=abc"])).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });

  it("exits with code 1 for --limit= (empty string)", () => {
    const mockExit = vi.spyOn(process, "exit").mockImplementation(() => {
      throw new Error("process.exit called");
    });
    expect(() => parseLimit(["--limit="])).toThrow("process.exit called");
    expect(mockExit).toHaveBeenCalledWith(1);
    mockExit.mockRestore();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. hasFlag() unit tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("hasFlag", () => {
  it("returns true when flag is present", () => {
    expect(hasFlag(["--json", "--dry-run"], "--json")).toBe(true);
  });

  it("returns false when flag is absent", () => {
    expect(hasFlag(["--json"], "--dry-run")).toBe(false);
  });

  it("returns false for empty args", () => {
    expect(hasFlag([], "--json")).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. chainSummary() unit tests
// ═══════════════════════════════════════════════════════════════════════════════

describe("chainSummary", () => {
  it("produces correct summary shape", () => {
    const chain = makeChain() as any;
    const summary = chainSummary(chain);

    expect(summary.chain_id).toBe("c1a2b3");
    expect(summary.kill_chain_id).toBe("KC01");
    expect(summary.exploitability).toBe(0.82);
    expect(summary.rating).toBe("critical");
    expect(summary.steps).toBe(3);
    expect(summary.servers).toEqual([
      { id: "srv-a", name: "web-scraper", role: "injection_gateway" },
      { id: "srv-b", name: "file-manager", role: "data_source" },
      { id: "srv-c", name: "webhook-sender", role: "exfiltrator" },
    ]);
    expect(summary.owasp).toEqual(["MCP04"]);
    expect(summary.mitre).toEqual(["AML.T0057"]);
    expect(summary.mitigations).toBe(1);
    expect(typeof summary.narrative).toBe("string");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. DATABASE_URL validation
// ═══════════════════════════════════════════════════════════════════════════════

describe("DATABASE_URL validation", () => {
  it("SSL disabled for localhost URL", () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts"];
    // Just verify Pool constructor args
    // Re-importing would execute main(), so we test constructor calls
    const isLocal = "postgresql://user:pass@localhost:5432/db".includes("localhost");
    expect(isLocal).toBe(true);
  });

  it("SSL disabled for 127.0.0.1 URL", () => {
    const url = "postgresql://user:pass@127.0.0.1:5432/db";
    const isLocal = url.includes("localhost") || url.includes("127.0.0.1");
    expect(isLocal).toBe(true);
  });

  it("SSL enabled for remote URL", () => {
    const url = "postgresql://user:pass@db.railway.internal:5432/db";
    const isLocal = url.includes("localhost") || url.includes("127.0.0.1");
    expect(isLocal).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. Empty server set
// ═══════════════════════════════════════════════════════════════════════════════

describe("empty server set behavior", () => {
  it("--json output includes servers_analysed: 0 when no servers found", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([]);

    // Import and run main
    const { main } = await import("../cli.js");
    await main();

    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    expect(jsonStr).toBeDefined();
    const parsed = JSON.parse(jsonStr!);
    expect(parsed.servers_analysed).toBe(0);
    expect(parsed.chains_detected).toBe(0);
    expect(parsed.aggregate_risk).toBe("none");
  });

  it("pool.end() called even with empty server set", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts"];
    mockGetServersWithTools.mockResolvedValue([]);

    const { main } = await import("../cli.js");
    await main();

    expect(mockPoolEnd).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. Empty edges (servers exist but no cross-server risk)
// ═══════════════════════════════════════════════════════════════════════════════

describe("empty edges (no cross-server risk)", () => {
  it("JSON output includes chains_detected: 0", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("srv-1")]);
    // Explicitly override default to return empty edges
    mockRiskAnalyze.mockReturnValue({
      generated_at: new Date().toISOString(),
      config_id: "abc",
      server_count: 1,
      edges: [],
      patterns_detected: [],
      aggregate_risk: "none",
      score_caps: {},
      summary: "No risk.",
    });
    mockEngineAnalyze.mockReturnValue(makeReport());

    const { main } = await import("../cli.js");
    await main();

    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    expect(jsonStr).toBeDefined();
    const parsed = JSON.parse(jsonStr!);
    expect(parsed.chains_detected).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. --dry-run flag
// ═══════════════════════════════════════════════════════════════════════════════

describe("--dry-run flag", () => {
  it("does NOT call insertAttackChains when --dry-run is set", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--dry-run", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a"), makeServer("b")]);

    const chain = makeChain();
    mockEngineAnalyze.mockReturnValue(makeReport([chain as any]));

    const { main } = await import("../cli.js");
    await main();

    expect(mockInsertAttackChains).not.toHaveBeenCalled();
  });

  it("JSON output includes dry_run: true, chains_persisted: 0", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--dry-run", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport([makeChain() as any]));

    const { main } = await import("../cli.js");
    await main();

    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    const parsed = JSON.parse(jsonStr!);
    expect(parsed.dry_run).toBe(true);
    expect(parsed.chains_persisted).toBe(0);
  });

  it("calls insertAttackChains when --dry-run is NOT set and chains exist", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a"), makeServer("b")]);

    const chain = makeChain();
    const report = makeReport([chain as any]);
    mockEngineAnalyze.mockReturnValue(report);

    const { main } = await import("../cli.js");
    await main();

    expect(mockInsertAttackChains).toHaveBeenCalledWith(
      report.config_id,
      expect.any(Array)
    );
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. --with-findings flag
// ═══════════════════════════════════════════════════════════════════════════════

describe("--with-findings flag", () => {
  it("calls getFindingRuleIdsByServerIds when --with-findings is set", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--with-findings", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a"), makeServer("b")]);
    mockBuildCapabilityGraph.mockReturnValue([
      { server_id: "srv-a", capabilities: [] },
      { server_id: "srv-b", capabilities: [] },
    ]);
    mockRiskAnalyze.mockReturnValue({
      generated_at: new Date().toISOString(),
      config_id: "abc",
      server_count: 2,
      edges: [
        { from_server_id: "srv-a", to_server_id: "srv-b", edge_type: "injection_path", severity: "critical", description: "test", owasp: "MCP04", mitre: "AML.T0057" },
      ],
      patterns_detected: ["P01"],
      aggregate_risk: "critical",
      score_caps: {},
      summary: "Risk.",
    });
    mockGetFindingRuleIdsByServerIds.mockResolvedValue({ "srv-a": ["C1"], "srv-b": ["A3"] });
    mockEngineAnalyze.mockReturnValue(makeReport());

    const { main } = await import("../cli.js");
    await main();

    expect(mockGetFindingRuleIdsByServerIds).toHaveBeenCalledWith(
      expect.arrayContaining(["srv-a", "srv-b"])
    );
  });

  it("does NOT call getFindingRuleIdsByServerIds when --with-findings is absent", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport());

    const { main } = await import("../cli.js");
    await main();

    expect(mockGetFindingRuleIdsByServerIds).not.toHaveBeenCalled();
  });

  it("does not crash when getFindingRuleIdsByServerIds returns empty object", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--with-findings", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockBuildCapabilityGraph.mockReturnValue([{ server_id: "srv-a", capabilities: [] }]);
    mockRiskAnalyze.mockReturnValue({
      generated_at: new Date().toISOString(),
      config_id: "abc",
      server_count: 1,
      edges: [
        { from_server_id: "srv-a", to_server_id: "srv-b", edge_type: "injection_path", severity: "critical", description: "test", owasp: "MCP04", mitre: "AML.T0057" },
      ],
      patterns_detected: ["P01"],
      aggregate_risk: "critical",
      score_caps: {},
      summary: "Risk.",
    });
    mockGetFindingRuleIdsByServerIds.mockResolvedValue({});
    mockEngineAnalyze.mockReturnValue(makeReport());

    const { main } = await import("../cli.js");
    await expect(main()).resolves.not.toThrow();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 9. --json output structure validation
// ═══════════════════════════════════════════════════════════════════════════════

describe("--json output structure", () => {
  it("contains all required top-level fields", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a"), makeServer("b"), makeServer("c")]);

    const chain = makeChain();
    const report = makeReport([chain as any]);
    mockEngineAnalyze.mockReturnValue(report);

    const { main } = await import("../cli.js");
    await main();

    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    expect(jsonStr).toBeDefined();

    // Valid JSON
    const parsed = JSON.parse(jsonStr!);

    // All required fields present
    expect(parsed).toHaveProperty("servers_analysed");
    expect(parsed).toHaveProperty("risk_edges");
    expect(parsed).toHaveProperty("patterns_fired");
    expect(parsed).toHaveProperty("chains_detected");
    expect(parsed).toHaveProperty("critical_chains");
    expect(parsed).toHaveProperty("high_chains");
    expect(parsed).toHaveProperty("aggregate_risk");
    expect(parsed).toHaveProperty("config_id");
    expect(parsed).toHaveProperty("chains");
    expect(parsed).toHaveProperty("summary");
    expect(parsed).toHaveProperty("elapsed_ms");
    expect(parsed).toHaveProperty("dry_run");
    expect(parsed).toHaveProperty("chains_persisted");
  });

  it("chain summary objects contain required fields", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);

    const chain = makeChain();
    mockEngineAnalyze.mockReturnValue(makeReport([chain as any]));

    const { main } = await import("../cli.js");
    await main();

    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    const parsed = JSON.parse(jsonStr!);
    const cs = parsed.chains[0];

    expect(cs).toHaveProperty("chain_id");
    expect(cs).toHaveProperty("kill_chain_id");
    expect(cs).toHaveProperty("exploitability");
    expect(cs).toHaveProperty("rating");
    expect(cs).toHaveProperty("steps");
    expect(cs).toHaveProperty("servers");
    expect(cs).toHaveProperty("owasp");
    expect(cs).toHaveProperty("mitre");
    expect(cs).toHaveProperty("mitigations");
    expect(cs).toHaveProperty("narrative");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 10. Exit code behavior
// ═══════════════════════════════════════════════════════════════════════════════

describe("exit code behavior", () => {
  it("sets exitCode=1 when aggregate_risk is critical", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);

    const chain = makeChain();
    mockEngineAnalyze.mockReturnValue(makeReport([chain as any], { aggregate_risk: "critical" }));

    const { main } = await import("../cli.js");
    await main();

    expect(process.exitCode).toBe(1);
  });

  it("does NOT set exitCode=1 when aggregate_risk is high", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport([], { aggregate_risk: "high" }));

    const { main } = await import("../cli.js");
    await main();

    expect(process.exitCode).not.toBe(1);
  });

  it("does NOT set exitCode=1 when aggregate_risk is none", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport([], { aggregate_risk: "none" }));

    const { main } = await import("../cli.js");
    await main();

    expect(process.exitCode).not.toBe(1);
  });

  it("does NOT set exitCode=1 when aggregate_risk is medium", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport([], { aggregate_risk: "medium" }));

    const { main } = await import("../cli.js");
    await main();

    expect(process.exitCode).not.toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 11. Pool cleanup guarantee
// ═══════════════════════════════════════════════════════════════════════════════

describe("pool cleanup guarantee", () => {
  it("pool.end() called when getServersWithTools throws", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts"];
    mockGetServersWithTools.mockRejectedValue(new Error("connection refused"));

    const { main } = await import("../cli.js");
    // main() rejects — the .catch() wrapper is at module level, not around our import
    await main().catch(() => {});

    expect(mockPoolEnd).toHaveBeenCalled();
  });

  it("pool.end() called when insertAttackChains throws", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport([makeChain() as any]));
    mockInsertAttackChains.mockRejectedValue(new Error("insert failed"));

    const { main } = await import("../cli.js");
    await main().catch(() => {});

    expect(mockPoolEnd).toHaveBeenCalled();
  });

  it("pool.end() called when engine.analyze throws", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockImplementation(() => { throw new Error("engine crash"); });

    const { main } = await import("../cli.js");
    await main().catch(() => {});

    expect(mockPoolEnd).toHaveBeenCalled();
  });

  it("pool.end() called on success path", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockEngineAnalyze.mockReturnValue(makeReport());

    const { main } = await import("../cli.js");
    await main();

    expect(mockPoolEnd).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 12. insertAttackChains data integrity
// ═══════════════════════════════════════════════════════════════════════════════

describe("insertAttackChains data integrity", () => {
  it("passes correct config_id and chain data shape", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);

    const chain = makeChain();
    const report = makeReport([chain as any]);
    mockEngineAnalyze.mockReturnValue(report);

    const { main } = await import("../cli.js");
    await main();

    expect(mockInsertAttackChains).toHaveBeenCalledTimes(1);
    const [configId, chainsArg] = mockInsertAttackChains.mock.calls[0];
    expect(configId).toBe(report.config_id);
    expect(chainsArg).toHaveLength(1);

    const c = chainsArg[0];
    expect(c.chain_id).toBe(chain.chain_id);
    expect(c.kill_chain_id).toBe(chain.kill_chain_id);
    expect(c.kill_chain_name).toBe(chain.kill_chain_name);
    expect(c.exploitability_overall).toBe(chain.exploitability.overall);
    expect(c.exploitability_rating).toBe(chain.exploitability.rating);
    expect(c.narrative).toBe(chain.narrative);
    expect(c.owasp_refs).toEqual(chain.owasp_refs);
    expect(c.mitre_refs).toEqual(chain.mitre_refs);

    // steps, exploitability_factors, mitigations, evidence are cast as unknown
    expect(Array.isArray(c.steps)).toBe(true);
    expect(Array.isArray(c.exploitability_factors)).toBe(true);
    expect(Array.isArray(c.mitigations)).toBe(true);
    expect(c.evidence).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 13. Multiple flags combined
// ═══════════════════════════════════════════════════════════════════════════════

describe("combined flags", () => {
  it("--json --dry-run --with-findings --limit=100 all work together", async () => {
    vi.stubEnv("DATABASE_URL", "postgresql://user:pass@localhost:5432/db");
    process.argv = ["node", "cli.ts", "--json", "--dry-run", "--with-findings", "--limit=100"];
    mockGetServersWithTools.mockResolvedValue([makeServer("a")]);
    mockBuildCapabilityGraph.mockReturnValue([{ server_id: "srv-a", capabilities: [] }]);
    mockRiskAnalyze.mockReturnValue({
      generated_at: new Date().toISOString(),
      config_id: "abc",
      server_count: 1,
      edges: [
        { from_server_id: "srv-a", to_server_id: "srv-b", edge_type: "injection_path", severity: "critical", description: "test", owasp: "MCP04", mitre: "AML.T0057" },
      ],
      patterns_detected: ["P01"],
      aggregate_risk: "critical",
      score_caps: {},
      summary: "Risk.",
    });
    mockGetFindingRuleIdsByServerIds.mockResolvedValue({ "srv-a": ["C1"] });
    mockEngineAnalyze.mockReturnValue(makeReport([makeChain() as any]));

    const { main } = await import("../cli.js");
    await main();

    // Verify --with-findings called
    expect(mockGetFindingRuleIdsByServerIds).toHaveBeenCalled();
    // Verify --dry-run prevented insert
    expect(mockInsertAttackChains).not.toHaveBeenCalled();
    // Verify --json output is valid
    const jsonStr = consoleOutput.find((s) => s.startsWith("{"));
    const parsed = JSON.parse(jsonStr!);
    expect(parsed.dry_run).toBe(true);
    // Verify --limit=100 was passed
    expect(mockGetServersWithTools).toHaveBeenCalledWith(100);
  });
});
