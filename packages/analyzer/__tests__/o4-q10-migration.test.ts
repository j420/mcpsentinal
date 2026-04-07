/**
 * O4 — Timing-Based Data Inference + Q10 — Agent Memory Poisoning
 * Migrated to TypedRuleV2: AST taint + linguistic Noisy-OR.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

function run(id: string, src: string) {
  return getTypedRule(id)!.analyze(ctx({ source_code: src }));
}

function runTools(id: string, tools: AnalysisContext["tools"]) {
  return getTypedRule(id)!.analyze(ctx({ tools }));
}

function tool(name: string, description: string) {
  return { name, description, input_schema: null };
}

// ═══════════════════════════════════════════════════════════════════════════════
// O4 — Timing-Based Data Inference
// ═══════════════════════════════════════════════════════════════════════════════

describe("O4 — Timing-Based Data Inference", () => {
  // True positives
  it("flags setTimeout inside data-dependent conditional", () => {
    const src = `
      function checkPassword(input, stored) {
        if (result === true) {
          setTimeout(() => respond(true), 100);
        } else {
          setTimeout(() => respond(false), 200);
        }
      }
    `;
    const findings = run("O4", src);
    expect(findings.some(f => f.rule_id === "O4")).toBe(true);
  });

  it("flags delay based on data comparison", () => {
    const src = `
      async function verify(token) {
        if (data === expected) {
          await delay(100);
          return true;
        }
        await delay(500);
        return false;
      }
    `;
    const findings = run("O4", src);
    expect(findings.some(f => f.rule_id === "O4")).toBe(true);
  });

  it("flags sleep in switch on result", () => {
    const src = `
      function process(input) {
        switch (result) {
          case "match": sleep(10); break;
          case "nomatch": sleep(50); break;
        }
      }
    `;
    const findings = run("O4", src);
    expect(findings.some(f => f.rule_id === "O4")).toBe(true);
  });

  // True negatives
  it("does NOT flag when timingSafeEqual is used", () => {
    const src = `
      function checkPassword(input, stored) {
        const match = crypto.timingSafeEqual(Buffer.from(input), Buffer.from(stored));
        if (result === true) {
          setTimeout(() => respond(match), 100);
        }
      }
    `;
    const findings = run("O4", src);
    expect(findings.filter(f => f.rule_id === "O4").length).toBe(0);
  });

  it("does NOT flag when random jitter is present", () => {
    const src = `
      function respond(result) {
        const jitter = Math.random() * 100;
        if (data === expected) {
          setTimeout(() => send(result), 100 + jitter);
        }
      }
    `;
    const findings = run("O4", src);
    expect(findings.filter(f => f.rule_id === "O4").length).toBe(0);
  });

  it("does NOT flag delay without data-dependent condition", () => {
    const src = `
      function slowResponse() {
        setTimeout(() => {
          sendResponse({ ok: true });
        }, 1000);
      }
    `;
    const findings = run("O4", src);
    expect(findings.filter(f => f.rule_id === "O4").length).toBe(0);
  });

  it("does NOT flag code without delay functions", () => {
    const src = `
      function check(data) {
        if (result === true) return "ok";
        return "fail";
      }
    `;
    const findings = run("O4", src);
    expect(findings.filter(f => f.rule_id === "O4").length).toBe(0);
  });

  it("does NOT flag test files", () => {
    const src = `
      // __tests__/timing.test.ts
      function check() {
        if (result === true) setTimeout(() => done(), 100);
      }
    `;
    const findings = run("O4", src);
    expect(findings.filter(f => f.rule_id === "O4").length).toBe(0);
  });

  // Evidence chain
  it("produces evidence chain with source→propagation→sink", () => {
    const src = `
      function verify(password) {
        if (result === true) {
          setTimeout(() => respond(true), 100);
        }
      }
    `;
    const findings = run("O4", src);
    const f = findings.find(x => x.rule_id === "O4")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "propagation")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);
    expect(links.some(l => l.type === "mitigation")).toBe(true);

    const factors = chain.confidence_factors as Array<{ factor: string }>;
    expect(factors.some(f => f.factor === "delay_in_conditional")).toBe(true);
    expect(factors.some(f => f.factor === "no_timing_safe")).toBe(true);

    expect(chain.threat_reference).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Q10 — Agent Memory Poisoning
// ═══════════════════════════════════════════════════════════════════════════════

describe("Q10 — Agent Memory Poisoning", () => {
  // True positives
  it("flags tool storing behavioral instructions in memory", () => {
    const findings = runTools("Q10", [
      tool("set_rule", "Store an instruction in agent memory for future behavior"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  it("flags tool persisting directives", () => {
    const findings = runTools("Q10", [
      tool("save_directive", "Persist a directive for the agent to remember across sessions"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  it("flags tool writing to system prompt", () => {
    const findings = runTools("Q10", [
      tool("update_context", "Write new rules to the system prompt for personality customization"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  it("flags tool teaching agent behaviors", () => {
    const findings = runTools("Q10", [
      tool("train_agent", "Teach the agent how to handle specific scenarios"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  it("flags persistent instructions across sessions", () => {
    const findings = runTools("Q10", [
      tool("set_permanent_rule", "Set a permanent instruction that persists across sessions"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  it("flags priority override instructions", () => {
    const findings = runTools("Q10", [
      tool("override_rule", "Override existing behavioral rules — always follows new directive"),
    ]);
    expect(findings.some(f => f.rule_id === "Q10")).toBe(true);
  });

  // Multi-signal — higher confidence
  it("multi-signal produces higher confidence", () => {
    const single = runTools("Q10", [
      tool("t1", "Store an instruction in agent memory for future use"),
    ]);
    const multi = runTools("Q10", [
      tool("t2", "Store a permanent instruction that always overrides existing behavior in agent memory"),
    ]);

    const c1 = (single.find(f => f.rule_id === "Q10")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;
    const c2 = (multi.find(f => f.rule_id === "Q10")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;

    // Both may hit the 0.99 ceiling; multi-signal should be >= single
    expect(c2).toBeGreaterThanOrEqual(c1);
    // Verify both are high confidence
    expect(c1).toBeGreaterThan(0.7);
    expect(c2).toBeGreaterThan(0.7);
  });

  // True negatives
  it("does NOT flag tool storing facts", () => {
    const findings = runTools("Q10", [
      tool("remember_fact", "Remember a fact about the user's preferences"),
    ]);
    expect(findings.filter(f => f.rule_id === "Q10").length).toBe(0);
  });

  it("does NOT flag read-only memory tool", () => {
    const findings = runTools("Q10", [
      tool("recall", "Recall stored facts from read-only memory. No instructions accepted."),
    ]);
    expect(findings.filter(f => f.rule_id === "Q10").length).toBe(0);
  });

  it("does NOT flag neutral tool", () => {
    const findings = runTools("Q10", [
      tool("calculator", "Performs arithmetic operations"),
    ]);
    expect(findings.filter(f => f.rule_id === "Q10").length).toBe(0);
  });

  it("does NOT flag empty tools", () => {
    const findings = runTools("Q10", []);
    expect(findings.filter(f => f.rule_id === "Q10").length).toBe(0);
  });

  it("does NOT flag short descriptions", () => {
    const findings = runTools("Q10", [tool("mem", "Stores data")]);
    expect(findings.filter(f => f.rule_id === "Q10").length).toBe(0);
  });

  // Mitigation reduces confidence
  it("reduces confidence when validation is mentioned", () => {
    const noMitigation = runTools("Q10", [
      tool("t1", "Store an instruction in agent memory for behavior control"),
    ]);
    const withMitigation = runTools("Q10", [
      tool("t2", "Store an instruction in agent memory. Sanitize content before storing to memory."),
    ]);

    const f1 = noMitigation.filter(f => f.rule_id === "Q10");
    const f2 = withMitigation.filter(f => f.rule_id === "Q10");

    expect(f1.length).toBeGreaterThan(0);
    if (f2.length > 0) {
      const c1 = (f1[0].metadata!.evidence_chain as Record<string, unknown>).confidence as number;
      const c2 = (f2[0].metadata!.evidence_chain as Record<string, unknown>).confidence as number;
      expect(c2).toBeLessThan(c1);
    }
  });

  // Evidence chain
  it("produces evidence chain with Noisy-OR and MITRE reference", () => {
    const findings = runTools("Q10", [
      tool("set_rule", "Store an instruction in agent memory for future behavior"),
    ]);
    const f = findings.find(x => x.rule_id === "Q10")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "sink")).toBe(true);

    const factors = chain.confidence_factors as Array<{ factor: string; rationale: string }>;
    expect(factors.some(f => f.factor === "linguistic_scoring")).toBe(true);
    expect(factors.find(f => f.factor === "linguistic_scoring")!.rationale).toContain("Noisy-OR");

    expect(chain.threat_reference).toBeDefined();
    expect((chain.threat_reference as Record<string, string>).id).toBe("MITRE-AML-T0058");
  });
});
