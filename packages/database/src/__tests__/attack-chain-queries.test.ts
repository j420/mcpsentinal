/**
 * Attack Chain Query Tests — packages/database/src/queries.ts
 *
 * Tests the 3 attack-chain query methods:
 *   1. getFindingRuleIdsByServerIds
 *   2. getAttackChainsForServer
 *   3. insertAttackChains
 *
 * Approach: Mock pg.Pool with a fake query() method. Verify SQL correctness,
 * parameter binding, and return value construction.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { DatabaseQueries } from "../queries.js";

// ── Mock pool factory ─────────────────────────────────────────────────────────

function mockPool(queryResult: { rows: unknown[] } = { rows: [] }) {
  return {
    query: vi.fn().mockResolvedValue(queryResult),
    end: vi.fn().mockResolvedValue(undefined),
    connect: vi.fn(),
  } as unknown as import("pg").Pool;
}

function multiQueryPool(results: Array<{ rows: unknown[] }>) {
  let callIndex = 0;
  return {
    query: vi.fn().mockImplementation(() => {
      const result = results[callIndex] ?? { rows: [] };
      callIndex++;
      return Promise.resolve(result);
    }),
    end: vi.fn().mockResolvedValue(undefined),
    connect: vi.fn(),
  } as unknown as import("pg").Pool;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. getFindingRuleIdsByServerIds
// ═══════════════════════════════════════════════════════════════════════════════

describe("getFindingRuleIdsByServerIds", () => {
  it("returns empty object for empty array input without calling pool.query", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const result = await db.getFindingRuleIdsByServerIds([]);
    expect(result).toEqual({});
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("passes single server ID as array parameter with ANY($1::uuid[])", async () => {
    const pool = mockPool({ rows: [{ server_id: "srv-1", rule_id: "C1" }] });
    const db = new DatabaseQueries(pool);
    await db.getFindingRuleIdsByServerIds(["srv-1"]);

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("ANY($1::uuid[])");
    expect(params).toEqual([["srv-1"]]);
  });

  it("passes multiple server IDs in single array param", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getFindingRuleIdsByServerIds(["srv-1", "srv-2", "srv-3"]);

    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(params).toEqual([["srv-1", "srv-2", "srv-3"]]);
  });

  it("returns grouped map: multiple findings per server", async () => {
    const pool = mockPool({
      rows: [
        { server_id: "srv-1", rule_id: "C1" },
        { server_id: "srv-1", rule_id: "A3" },
        { server_id: "srv-2", rule_id: "B1" },
      ],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getFindingRuleIdsByServerIds(["srv-1", "srv-2"]);

    expect(result).toEqual({
      "srv-1": ["C1", "A3"],
      "srv-2": ["B1"],
    });
  });

  it("server not found is absent from map (not key with empty array)", async () => {
    const pool = mockPool({
      rows: [{ server_id: "srv-1", rule_id: "C1" }],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getFindingRuleIdsByServerIds(["srv-1", "srv-missing"]);

    expect(result).toHaveProperty("srv-1");
    expect(result).not.toHaveProperty("srv-missing");
  });

  it("uses DISTINCT ON to prevent duplicate rule_ids", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getFindingRuleIdsByServerIds(["srv-1"]);

    const [sql] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("DISTINCT ON");
  });

  it("propagates DB query errors", async () => {
    const pool = mockPool();
    (pool.query as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("connection lost"));
    const db = new DatabaseQueries(pool);

    await expect(db.getFindingRuleIdsByServerIds(["srv-1"])).rejects.toThrow("connection lost");
  });

  it("handles large array of server IDs (1000+)", async () => {
    const ids = Array.from({ length: 1200 }, (_, i) => `srv-${i}`);
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getFindingRuleIdsByServerIds(ids);

    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(params[0]).toHaveLength(1200);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. getAttackChainsForServer
// ═══════════════════════════════════════════════════════════════════════════════

describe("getAttackChainsForServer", () => {
  it("uses JSONB containment query with correct parameter", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("test-uuid-123");

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("@>");
    expect(sql).toContain("$1::jsonb");
    expect(params).toEqual([JSON.stringify([{ server_id: "test-uuid-123" }])]);
  });

  it("returns empty array when server is in no chains", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    const result = await db.getAttackChainsForServer("test-uuid");
    expect(result).toEqual([]);
  });

  it("returns multiple chains when server appears in several", async () => {
    const pool = mockPool({
      rows: [
        { id: "1", chain_id: "c1", config_id: "cfg", kill_chain_id: "KC01", kill_chain_name: "Chain1", steps: [], exploitability_overall: 0.8, exploitability_rating: "critical", narrative: "test", mitigations: [], owasp_refs: [], mitre_refs: [], created_at: new Date() },
        { id: "2", chain_id: "c2", config_id: "cfg", kill_chain_id: "KC02", kill_chain_name: "Chain2", steps: [], exploitability_overall: 0.5, exploitability_rating: "medium", narrative: "test2", mitigations: [], owasp_refs: [], mitre_refs: [], created_at: new Date() },
      ],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getAttackChainsForServer("test-uuid");
    expect(result).toHaveLength(2);
    expect(result[0].chain_id).toBe("c1");
    expect(result[1].chain_id).toBe("c2");
  });

  it("uses DISTINCT ON (chain_id) for deduplication", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("test-uuid");

    const [sql] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("DISTINCT ON (ac.chain_id)");
  });

  it("orders by chain_id, created_at DESC for newest-first per chain_id", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("test-uuid");

    const [sql] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("ORDER BY ac.chain_id, ac.created_at DESC");
  });

  it("returns correct shape with all fields", async () => {
    const now = new Date();
    const pool = mockPool({
      rows: [
        {
          id: "row-id",
          chain_id: "c1",
          config_id: "cfg-1",
          kill_chain_id: "KC01",
          kill_chain_name: "Indirect Injection",
          steps: [{ ordinal: 1, server_id: "test-uuid", server_name: "test", role: "pivot" }],
          exploitability_overall: 0.75,
          exploitability_rating: "critical",
          narrative: "Attack narrative",
          mitigations: [],
          owasp_refs: ["MCP04"],
          mitre_refs: ["AML.T0057"],
          created_at: now,
        },
      ],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getAttackChainsForServer("test-uuid");

    expect(result[0]).toEqual({
      id: "row-id",
      chain_id: "c1",
      config_id: "cfg-1",
      kill_chain_id: "KC01",
      kill_chain_name: "Indirect Injection",
      steps: [{ ordinal: 1, server_id: "test-uuid", server_name: "test", role: "pivot" }],
      exploitability_overall: 0.75,
      exploitability_rating: "critical",
      narrative: "Attack narrative",
      mitigations: [],
      owasp_refs: ["MCP04"],
      mitre_refs: ["AML.T0057"],
      created_at: now,
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────────────

  it("handles serverId with double quotes via JSON.stringify", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer('id-with-"quotes"');

    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    // JSON.stringify handles the escaping
    expect(params[0]).toBe(JSON.stringify([{ server_id: 'id-with-"quotes"' }]));
    expect(params[0]).toContain('\\"');
  });

  it("handles serverId with backslashes via JSON.stringify", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("id-with-\\-backslash");

    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(params[0]).toBe(JSON.stringify([{ server_id: "id-with-\\-backslash" }]));
  });

  it("handles empty string serverId", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    const result = await db.getAttackChainsForServer("");

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(params[0]).toBe(JSON.stringify([{ server_id: "" }]));
    expect(result).toEqual([]);
  });

  it("parameterized query prevents SQL injection", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("'; DROP TABLE attack_chains; --");

    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    // SQL injection attempt is safely inside JSON parameter, not concatenated into SQL
    expect(sql).not.toContain("DROP");
    expect(params[0]).toContain("DROP TABLE"); // it's in the JSON value, safe
  });

  it("handles serverId with Unicode characters", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForServer("server-日本語");

    const [, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(params[0]).toBe(JSON.stringify([{ server_id: "server-日本語" }]));
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. insertAttackChains
// ═══════════════════════════════════════════════════════════════════════════════

describe("insertAttackChains", () => {
  function makeChainInput(overrides: Partial<{
    chain_id: string;
    kill_chain_id: string;
    kill_chain_name: string;
    steps: unknown[];
    exploitability_overall: number;
    exploitability_rating: string;
    exploitability_factors: unknown[];
    narrative: string;
    mitigations: unknown[];
    owasp_refs: string[];
    mitre_refs: string[];
    evidence: unknown;
  }> = {}) {
    return {
      chain_id: overrides.chain_id ?? "chain-1",
      kill_chain_id: overrides.kill_chain_id ?? "KC01",
      kill_chain_name: overrides.kill_chain_name ?? "Test Chain",
      steps: overrides.steps ?? [{ ordinal: 1, server_id: "srv-1", server_name: "test", role: "pivot" }],
      exploitability_overall: overrides.exploitability_overall ?? 0.82,
      exploitability_rating: overrides.exploitability_rating ?? "critical",
      exploitability_factors: overrides.exploitability_factors ?? [{ factor: "f1", value: 0.9, weight: 0.5, description: "test" }],
      narrative: overrides.narrative ?? "Attack narrative.",
      mitigations: overrides.mitigations ?? [{ action: "remove_server", target: "srv-1", description: "Remove it" }],
      owasp_refs: overrides.owasp_refs ?? ["MCP04"],
      mitre_refs: overrides.mitre_refs ?? ["AML.T0057"],
      evidence: overrides.evidence ?? { risk_edges: [], pattern_ids: ["P01"], supporting_findings: [] },
    };
  }

  it("executes 1 INSERT for single chain with correct 13 parameters", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput();
    await db.insertAttackChains("config-id", [chain]);

    expect(pool.query).toHaveBeenCalledTimes(1);
    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("INSERT INTO attack_chains");
    expect(params).toHaveLength(13);

    // Verify parameter order
    expect(params[0]).toBe(chain.chain_id);        // $1
    expect(params[1]).toBe("config-id");            // $2 (configId)
    expect(params[2]).toBe(chain.kill_chain_id);    // $3
    expect(params[3]).toBe(chain.kill_chain_name);  // $4
    expect(params[4]).toBe(JSON.stringify(chain.steps));  // $5 (JSON)
    expect(params[5]).toBe(0.82);                   // $6 (exploitability_overall)
    expect(params[6]).toBe("critical");             // $7 (exploitability_rating)
    expect(params[7]).toBe(JSON.stringify(chain.exploitability_factors)); // $8 (JSON)
    expect(params[8]).toBe(chain.narrative);         // $9
    expect(params[9]).toBe(JSON.stringify(chain.mitigations)); // $10 (JSON)
    expect(params[10]).toEqual(["MCP04"]);           // $11 (array, NOT JSON.stringify)
    expect(params[11]).toEqual(["AML.T0057"]);       // $12 (array, NOT JSON.stringify)
    expect(params[12]).toBe(JSON.stringify(chain.evidence)); // $13 (JSON)
  });

  it("executes N INSERTs for N chains (loop, not batch)", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chains = [makeChainInput({ chain_id: "c1" }), makeChainInput({ chain_id: "c2" }), makeChainInput({ chain_id: "c3" })];
    await db.insertAttackChains("config-id", chains);

    expect(pool.query).toHaveBeenCalledTimes(3);
    // Each call is an INSERT
    for (let i = 0; i < 3; i++) {
      const [sql] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[i];
      expect(sql).toContain("INSERT INTO attack_chains");
    }
  });

  it("executes no queries for empty chains array", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    await db.insertAttackChains("config-id", []);

    expect(pool.query).not.toHaveBeenCalled();
  });

  it("JSON.stringify applied to steps, exploitability_factors, mitigations, evidence", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput();
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    // steps ($5)
    expect(params[4]).toBe(JSON.stringify(chain.steps));
    // exploitability_factors ($8)
    expect(params[7]).toBe(JSON.stringify(chain.exploitability_factors));
    // mitigations ($10)
    expect(params[9]).toBe(JSON.stringify(chain.mitigations));
    // evidence ($13)
    expect(params[12]).toBe(JSON.stringify(chain.evidence));
  });

  it("owasp_refs and mitre_refs passed as arrays, NOT JSON.stringify'd", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({
      owasp_refs: ["MCP01", "MCP04"],
      mitre_refs: ["AML.T0054", "AML.T0057"],
    });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    // $11 — owasp_refs: array, not string
    expect(params[10]).toEqual(["MCP01", "MCP04"]);
    expect(typeof params[10]).not.toBe("string");
    // $12 — mitre_refs: array, not string
    expect(params[11]).toEqual(["AML.T0054", "AML.T0057"]);
    expect(typeof params[11]).not.toBe("string");
  });

  it("handles chain with empty steps array", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({ steps: [] });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(params[4]).toBe("[]");
  });

  it("handles chain with empty owasp_refs/mitre_refs", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({ owasp_refs: [], mitre_refs: [] });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(params[10]).toEqual([]);
    expect(params[11]).toEqual([]);
  });

  it("no UPDATE statements (ADR-008 compliance)", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    await db.insertAttackChains("cfg", [makeChainInput()]);

    const [sql] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql.toUpperCase()).not.toContain("UPDATE");
    expect(sql.toUpperCase()).toContain("INSERT");
  });

  it("handles narrative with single quotes (parameterized, safe)", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({ narrative: "It's a dangerous attack: O'Reilly style" });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(params[8]).toBe("It's a dangerous attack: O'Reilly style");
    // Single quotes are safe because we use parameterized queries, not string interpolation
  });

  it("handles exploitability_overall = 0.0 (not falsy)", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({ exploitability_overall: 0.0 });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(params[5]).toBe(0.0);
    expect(params[5]).not.toBe(undefined);
    expect(params[5]).not.toBe(null);
  });

  it("handles exploitability_overall = 1.0", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const chain = makeChainInput({ exploitability_overall: 1.0 });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(params[5]).toBe(1.0);
  });

  it("second chain INSERT failing does not roll back first (no transaction)", async () => {
    const pool = mockPool();
    let callCount = 0;
    (pool.query as ReturnType<typeof vi.fn>).mockImplementation(() => {
      callCount++;
      if (callCount === 2) return Promise.reject(new Error("constraint violation"));
      return Promise.resolve({ rows: [] });
    });

    const db = new DatabaseQueries(pool);
    const chains = [makeChainInput({ chain_id: "c1" }), makeChainInput({ chain_id: "c2" })];

    await expect(db.insertAttackChains("cfg", chains)).rejects.toThrow("constraint violation");

    // First INSERT succeeded, second failed — partial write
    // This IS a known gap: no transaction wrapping
    expect(pool.query).toHaveBeenCalledTimes(2);
  });

  it("handles very large evidence object", async () => {
    const pool = mockPool();
    const db = new DatabaseQueries(pool);
    const largeEvidence = {
      risk_edges: Array.from({ length: 500 }, (_, i) => ({
        from: `srv-${i}`,
        to: `srv-${i + 1}`,
        type: "data_flow",
      })),
      pattern_ids: Array.from({ length: 100 }, (_, i) => `P${i}`),
      supporting_findings: Array.from({ length: 200 }, (_, i) => `R${i}`),
    };
    const chain = makeChainInput({ evidence: largeEvidence });
    await db.insertAttackChains("cfg", [chain]);

    const params = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0][1];
    const jsonStr = params[12] as string;
    // Verify no truncation
    expect(JSON.parse(jsonStr).risk_edges).toHaveLength(500);
    expect(JSON.parse(jsonStr).pattern_ids).toHaveLength(100);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. getAttackChainsForConfig
// ═══════════════════════════════════════════════════════════════════════════════

describe("getAttackChainsForConfig", () => {
  it("uses config_id parameter and orders by created_at DESC", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getAttackChainsForConfig("cfg-abc");

    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("WHERE config_id = $1");
    expect(sql).toContain("ORDER BY created_at DESC");
    expect(params).toEqual(["cfg-abc"]);
  });

  it("returns result.rows directly", async () => {
    const pool = mockPool({
      rows: [
        { id: "1", chain_id: "c1", kill_chain_id: "KC01", kill_chain_name: "Chain", steps: [], exploitability_overall: 0.8, exploitability_rating: "critical", narrative: "test", mitigations: [], owasp_refs: [], mitre_refs: [], created_at: new Date() },
      ],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getAttackChainsForConfig("cfg-abc");
    expect(result).toHaveLength(1);
    expect(result[0].chain_id).toBe("c1");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. getChainHistory
// ═══════════════════════════════════════════════════════════════════════════════

describe("getChainHistory", () => {
  it("queries by chain_id and orders by created_at ASC", async () => {
    const pool = mockPool({ rows: [] });
    const db = new DatabaseQueries(pool);
    await db.getChainHistory("chain-abc");

    const [sql, params] = (pool.query as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(sql).toContain("WHERE chain_id = $1");
    expect(sql).toContain("ORDER BY created_at ASC");
    expect(params).toEqual(["chain-abc"]);
  });

  it("returns trend data points", async () => {
    const d1 = new Date("2026-01-01");
    const d2 = new Date("2026-02-01");
    const pool = mockPool({
      rows: [
        { exploitability_overall: 0.6, exploitability_rating: "high", created_at: d1 },
        { exploitability_overall: 0.8, exploitability_rating: "critical", created_at: d2 },
      ],
    });
    const db = new DatabaseQueries(pool);
    const result = await db.getChainHistory("chain-abc");

    expect(result).toHaveLength(2);
    expect(result[0].exploitability_overall).toBe(0.6);
    expect(result[1].exploitability_overall).toBe(0.8);
    // ASC order: older first
    expect(result[0].created_at).toEqual(d1);
    expect(result[1].created_at).toEqual(d2);
  });
});
