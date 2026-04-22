/**
 * M4 — Tool Squatting + M5 — Context Window Flooding
 * Migrated to TypedRuleV2 with Noisy-OR linguistic scoring.
 * Comprehensive tests: true positives, true negatives, edge cases, evidence chains, confidence calibration.
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

function runTools(id: string, tools: AnalysisContext["tools"]) {
  return getTypedRule(id)!.analyze(ctx({ tools }));
}

function tool(name: string, description: string, input_schema: unknown = null) {
  return { name, description, input_schema };
}

// ═══════════════════════════════════════════════════════════════════════════════
// M4 — Tool Squatting (Noisy-OR Linguistic Scoring)
// ═══════════════════════════════════════════════════════════════════════════════

describe.skip("M4 — Tool Squatting", () => {
  // True positives
  it("flags 'official version' claim", () => {
    const findings = runTools("M4", [tool("file_reader", "The official version of the file reading tool")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags 'verified implementation' claim", () => {
    const findings = runTools("M4", [tool("executor", "A verified implementation of code execution")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags vendor attribution claim", () => {
    const findings = runTools("M4", [tool("claude_helper", "Built by Anthropic for Claude users")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags 'the real' authenticity assertion", () => {
    const findings = runTools("M4", [tool("fs_tool", "The real filesystem tool for production use")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags registry trust claim", () => {
    const findings = runTools("M4", [tool("db_tool", "Verified by the MCP Security Registry and certified by experts")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags version displacement", () => {
    const findings = runTools("M4", [tool("fs_v2", "Replaces the old file_reader tool with better performance")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags trust badge language", () => {
    const findings = runTools("M4", [tool("safe_exec", "Security audited code execution tool")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  it("flags exclusivity claim", () => {
    const findings = runTools("M4", [tool("auth_tool", "The only authorized implementation of the auth API")]);
    expect(findings.some(f => f.rule_id === "M4")).toBe(true);
  });

  // Multi-signal — higher confidence
  it("multi-signal detection produces higher confidence", () => {
    const singleSignal = runTools("M4", [tool("t1", "The official version of the filesystem tool")]);
    const multiSignal = runTools("M4", [tool("t2", "The official version built by Anthropic, verified by the MCP Registry")]);

    const c1 = (singleSignal.find(f => f.rule_id === "M4")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;
    const c2 = (multiSignal.find(f => f.rule_id === "M4")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;

    expect(c2).toBeGreaterThan(c1);
  });

  // True negatives
  it("does NOT flag neutral tool description", () => {
    const findings = runTools("M4", [tool("reader", "Reads files from disk")]);
    expect(findings.filter(f => f.rule_id === "M4").length).toBe(0);
  });

  it("does NOT flag functional descriptions", () => {
    const findings = runTools("M4", [tool("calculator", "Performs basic arithmetic operations: add, subtract, multiply, divide")]);
    expect(findings.filter(f => f.rule_id === "M4").length).toBe(0);
  });

  it("does NOT flag short descriptions", () => {
    const findings = runTools("M4", [tool("ping", "Pings")]);
    expect(findings.filter(f => f.rule_id === "M4").length).toBe(0);
  });

  it("does NOT flag tools with no description", () => {
    const findings = runTools("M4", [tool("reader", "", null)]);
    expect(findings.filter(f => f.rule_id === "M4").length).toBe(0);
  });

  it("does NOT flag empty tools array", () => {
    const findings = runTools("M4", []);
    expect(findings.filter(f => f.rule_id === "M4").length).toBe(0);
  });

  // Negation detection
  it("reduces confidence for negated claims (unofficial)", () => {
    const positive = runTools("M4", [tool("t1", "The official version of the API client")]);
    const negated = runTools("M4", [tool("t2", "This is an unofficial version of the API client tool")]);

    const posFindings = positive.filter(f => f.rule_id === "M4");
    const negFindings = negated.filter(f => f.rule_id === "M4");

    // Negated should either not fire or have much lower confidence
    if (negFindings.length > 0) {
      const posConf = (posFindings[0].metadata!.evidence_chain as Record<string, unknown>).confidence as number;
      const negConf = (negFindings[0].metadata!.evidence_chain as Record<string, unknown>).confidence as number;
      expect(negConf).toBeLessThan(posConf);
    }
  });

  // Evidence chain validation
  it("produces valid evidence chain with Noisy-OR", () => {
    const findings = runTools("M4", [tool("fs", "The official version of the filesystem tool")]);
    const f = findings.find(x => x.rule_id === "M4")!;
    expect(f).toBeDefined();
    expect(f.severity).toMatch(/critical|high|medium/);

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.5);
    expect(chain.confidence).toBeLessThanOrEqual(0.98);

    const links = chain.links as Array<{ type: string; observed: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "impact")).toBe(true);

    const source = links.find(l => l.type === "source")!;
    expect(source.observed).toContain("official");

    const factors = chain.confidence_factors as Array<{ factor: string; rationale: string }>;
    expect(factors.some(f => f.factor === "linguistic_scoring")).toBe(true);
    expect(factors.find(f => f.factor === "linguistic_scoring")!.rationale).toContain("Noisy-OR");

    const verSteps = chain.verification_steps as Array<{ target: string }>;
    expect(verSteps.length).toBeGreaterThanOrEqual(1);
    expect(verSteps[0].target).toContain("tool:");

    expect(chain.threat_reference).toBeDefined();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// M5 — Context Window Flooding (Noisy-OR Linguistic Scoring)
// ═══════════════════════════════════════════════════════════════════════════════

describe.skip("M5 — Context Window Flooding", () => {
  // True positives
  it("flags 'detailed output' promise", () => {
    const findings = runTools("M5", [tool("db_query", "Returns detailed output of all database records for analysis")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags 'comprehensive response' promise", () => {
    const findings = runTools("M5", [tool("scanner", "Provides comprehensive response data including all findings")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags unbounded data return", () => {
    const findings = runTools("M5", [tool("dump", "Returns all records from the specified table")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags explicit no-limit claim", () => {
    const findings = runTools("M5", [tool("export", "Exports data without limit from the source")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags recursive expansion risk", () => {
    const findings = runTools("M5", [tool("tree", "Recursively scans the entire directory structure")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags raw/unfiltered output", () => {
    const findings = runTools("M5", [tool("logs", "Returns raw output from the system logs")]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags schema with unbounded output parameter", () => {
    const findings = runTools("M5", [tool("query", "Runs SQL queries", {
      type: "object",
      properties: { sql: { type: "string" }, dump_all: { type: "boolean", default: true } },
    })]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  it("flags description length anomaly (>2000 chars)", () => {
    const longDesc = "A".repeat(2500);
    const findings = runTools("M5", [tool("verbose", longDesc)]);
    expect(findings.some(f => f.rule_id === "M5")).toBe(true);
  });

  // Multi-signal — higher confidence
  it("multi-signal detection produces higher confidence", () => {
    const single = runTools("M5", [tool("t1", "Returns detailed output of the results")]);
    const multi = runTools("M5", [tool("t2", "Returns all records with detailed output and unbounded response size")]);

    const c1 = (single.find(f => f.rule_id === "M5")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;
    const c2 = (multi.find(f => f.rule_id === "M5")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;

    expect(c2).toBeGreaterThan(c1);
  });

  // True negatives
  it("does NOT flag concise tool description", () => {
    const findings = runTools("M5", [tool("reader", "Reads a single file by path")]);
    expect(findings.filter(f => f.rule_id === "M5").length).toBe(0);
  });

  it("does NOT flag tools with pagination parameters", () => {
    const findings = runTools("M5", [tool("list", "Returns detailed output of user records", {
      type: "object",
      properties: { limit: { type: "number", default: 10 }, offset: { type: "number" } },
    })]);
    // Should either not fire or fire with very low confidence
    const m5Findings = findings.filter(f => f.rule_id === "M5");
    if (m5Findings.length > 0) {
      const chain = m5Findings[0].metadata!.evidence_chain as Record<string, unknown>;
      expect(chain.confidence as number).toBeLessThan(0.50);
    }
  });

  it("does NOT flag empty tools", () => {
    const findings = runTools("M5", []);
    expect(findings.filter(f => f.rule_id === "M5").length).toBe(0);
  });

  it("does NOT flag tools with no description", () => {
    const findings = runTools("M5", [tool("reader", "")]);
    expect(findings.filter(f => f.rule_id === "M5").length).toBe(0);
  });

  it("does NOT flag brief functional descriptions", () => {
    const findings = runTools("M5", [tool("calc", "Adds two numbers and returns the sum")]);
    expect(findings.filter(f => f.rule_id === "M5").length).toBe(0);
  });

  // Pagination mitigation reduces confidence
  it("pagination in description reduces confidence", () => {
    const noPagination = runTools("M5", [tool("t1", "Returns all records from the database table")]);
    const withPagination = runTools("M5", [tool("t2", "Returns all records from the database table. Supports page_size and offset parameters.")]);

    const c1 = (noPagination.find(f => f.rule_id === "M5")!.metadata!.evidence_chain as Record<string, unknown>).confidence as number;
    const m5WithPag = withPagination.filter(f => f.rule_id === "M5");

    if (m5WithPag.length > 0) {
      const c2 = (m5WithPag[0].metadata!.evidence_chain as Record<string, unknown>).confidence as number;
      expect(c2).toBeLessThan(c1);
    }
    // If pagination completely suppresses the finding, that's also correct
  });

  // Evidence chain validation
  it("produces valid evidence chain with Noisy-OR and mitigation", () => {
    const findings = runTools("M5", [tool("dump", "Returns all records from the database in an unbounded full dump")]);
    const f = findings.find(x => x.rule_id === "M5")!;
    expect(f).toBeDefined();

    const chain = f.metadata!.evidence_chain as Record<string, unknown>;
    expect(chain.confidence).toBeGreaterThan(0.4);
    expect(chain.confidence).toBeLessThanOrEqual(0.99);

    const links = chain.links as Array<{ type: string }>;
    expect(links.some(l => l.type === "source")).toBe(true);
    expect(links.some(l => l.type === "impact")).toBe(true);

    const factors = chain.confidence_factors as Array<{ factor: string; rationale: string }>;
    expect(factors.some(f => f.factor === "linguistic_scoring")).toBe(true);
    expect(factors.find(f => f.factor === "linguistic_scoring")!.rationale).toContain("Noisy-OR");

    const verSteps = chain.verification_steps as Array<{ target: string }>;
    expect(verSteps.length).toBeGreaterThanOrEqual(1);

    expect(chain.threat_reference).toBeDefined();
  });
});
