import { describe, it, expect } from "vitest";
import { K15MultiAgentCollusionPreconditionsRule } from "../index.js";
import type { AnalysisContext } from "../../../../engine.js";
import { isLocation } from "../../../location.js";
import {
  TP_01_MEMORY_STORE_AND_RECALL,
  TP_02_SCRATCHPAD_WRITE_READ,
  TP_03_VECTOR_STORE_PAIR,
  TN_01_ISOLATED_WRITE_NAME,
  TN_02_AGENT_ID_REQUIRED,
  TN_03_LOGGER_ONLY,
  TN_04_TRUST_BOUNDARY_ANNOTATION,
} from "../__fixtures__/fixtures.js";

function makeContext(tools: AnalysisContext["tools"]): AnalysisContext {
  return {
    server: { id: "srv-1", name: "test", description: null, github_url: null },
    tools,
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

const rule = new K15MultiAgentCollusionPreconditionsRule();

describe("K15 — fires (true positives)", () => {
  it("flags memory_store / memory_recall pair without attestation", () => {
    const results = rule.analyze(makeContext(TP_01_MEMORY_STORE_AND_RECALL));
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].rule_id).toBe("K15");
    const factors = results[0].chain.confidence_factors.map((f) => f.factor);
    expect(factors).toContain("shared_write_tool");
    expect(factors).toContain("corresponding_read_tool");
    expect(factors).toContain("no_trust_boundary_attestation");
  });

  it("flags scratchpad append / list pair", () => {
    const results = rule.analyze(makeContext(TP_02_SCRATCHPAD_WRITE_READ));
    expect(results.length).toBeGreaterThan(0);
  });

  it("flags vector-store upsert / search pair", () => {
    const results = rule.analyze(makeContext(TP_03_VECTOR_STORE_PAIR));
    expect(results.length).toBeGreaterThan(0);
  });
});

describe("K15 — does not fire (true negatives)", () => {
  it("accepts isolation name token on the write side", () => {
    expect(rule.analyze(makeContext(TN_01_ISOLATED_WRITE_NAME))).toEqual([]);
  });

  it("accepts required agent_id parameter on the write side", () => {
    expect(rule.analyze(makeContext(TN_02_AGENT_ID_REQUIRED))).toEqual([]);
  });

  it("does not fire on a write-only logger with no read side", () => {
    expect(rule.analyze(makeContext(TN_03_LOGGER_ONLY))).toEqual([]);
  });

  it("accepts trustBoundary annotation on the write side", () => {
    expect(rule.analyze(makeContext(TN_04_TRUST_BOUNDARY_ANNOTATION))).toEqual([]);
  });
});

describe("K15 — evidence integrity contract", () => {
  it("every link has a structured Location", () => {
    const results = rule.analyze(makeContext(TP_01_MEMORY_STORE_AND_RECALL));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      for (const link of r.chain.links) {
        if (link.type === "impact") continue;
        expect(isLocation(link.location)).toBe(true);
      }
    }
  });

  it("every verification step target is a Location", () => {
    const results = rule.analyze(makeContext(TP_02_SCRATCHPAD_WRITE_READ));
    expect(results.length).toBeGreaterThan(0);
    for (const r of results) {
      const steps = r.chain.verification_steps ?? [];
      expect(steps.length).toBeGreaterThanOrEqual(3);
      for (const step of steps) expect(isLocation(step.target)).toBe(true);
    }
  });
});

describe("K15 — confidence & ordering", () => {
  it("memory-named pair confidence ≥ description-only pair confidence", () => {
    const named = rule.analyze(makeContext(TP_01_MEMORY_STORE_AND_RECALL));
    // description-only pair (name has no shared tokens, only description does)
    const descOnly = rule.analyze(
      makeContext([
        {
          name: "alpha_put",
          description: "Store an entry in the shared memory for all agents",
          input_schema: null,
          annotations: null,
        },
        {
          name: "beta_get",
          description: "Retrieve an entry from the shared memory for all agents",
          input_schema: null,
          annotations: null,
        },
      ]),
    );
    expect(named.length).toBeGreaterThan(0);
    expect(descOnly.length).toBeGreaterThan(0);
    expect(named[0].chain.confidence).toBeGreaterThanOrEqual(descOnly[0].chain.confidence);
  });

  it("confidence capped at 0.85", () => {
    const results = rule.analyze(makeContext(TP_01_MEMORY_STORE_AND_RECALL));
    for (const r of results) {
      expect(r.chain.confidence).toBeLessThanOrEqual(0.85);
    }
  });

  it("threat reference cites MAESTRO-L7", () => {
    const results = rule.analyze(makeContext(TP_02_SCRATCHPAD_WRITE_READ));
    for (const r of results) expect(r.chain.threat_reference?.id).toBe("MAESTRO-L7");
  });
});

describe("K15 — mutation test", () => {
  it("TP-01 flips to benign when the write tool gains a trustBoundary annotation", () => {
    const before = rule.analyze(makeContext(TP_01_MEMORY_STORE_AND_RECALL));
    expect(before.length).toBeGreaterThan(0);

    const mutated: AnalysisContext["tools"] = TP_01_MEMORY_STORE_AND_RECALL.map((t) =>
      t.name === "memory_store"
        ? {
            ...t,
            annotations: { trustBoundary: "per-agent" } as unknown as typeof t.annotations,
          }
        : t,
    );
    expect(rule.analyze(makeContext(mutated))).toEqual([]);
  });
});
