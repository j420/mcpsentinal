/**
 * Dynamic Confidence — K1 (Absent Structured Logging)
 *
 * Proves that the compliance-remaining-detector's evidence chain produces
 * genuinely different confidence values based on server context, not the
 * old hardcoded 0.75.
 *
 * K1 uses buildRule() factory → EvidenceChainBuilder with source+propagation+sink
 * (base 0.70) + structural_match (-0.05) + 5 server-specific signals from
 * computeCodeSignals(): match specificity, code location, nearby mitigation,
 * tool correlation, exposure surface.
 *
 * Server A: network-exposed payment processor, handler code, user input,
 *   no mitigations, dangerous tools, SSE+no auth → high confidence.
 * Server B: local dev helper, setup code, static values, stdio → low confidence.
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return { server: { id: "t", name: "test", description: null, github_url: null }, tools: [], source_code: null, dependencies: [], connection_metadata: null, ...overrides };
}
function run(id: string, c: AnalysisContext) { return getTypedRule(id)!.analyze(c); }

describe("K1 — Dynamic confidence across server contexts", () => {
  it("network-exposed payment server with handler code → higher confidence than local dev helper with setup code", () => {
    // Server A: SSE transport, no auth, handler code with req.body (user input),
    // tools that correlate with logging category (writes-data patterns)
    const serverA = ctx({
      server: { id: "payment-srv", name: "payment-processor", description: "Process payments", github_url: null },
      tools: [
        { name: "execute_payment", description: "Execute a payment transaction", input_schema: { type: "object" } },
        { name: "update_ledger", description: "Update the financial ledger", input_schema: { type: "object" } },
      ],
      source_code: `
async function handleTool(req, res) {
  console.log("request handling", req.body.action);
  const result = await processPayment(req.body);
  res.json(result);
}
`,
      connection_metadata: { auth_required: false, transport: "sse", response_time_ms: 100 },
    });

    // Server B: stdio transport, setup/init code with static string,
    // single read-only tool (no writes-data correlation for K1's logging category)
    const serverB = ctx({
      server: { id: "dev-helper", name: "dev-helper", description: "Local development helper", github_url: null },
      tools: [
        { name: "get_status", description: "Get development server status", input_schema: { type: "object" } },
      ],
      source_code: `
// setup.ts
function initServer() {
  console.log("request handling started");
}
export default initServer;
`,
      connection_metadata: { auth_required: false, transport: "stdio", response_time_ms: 10 },
    });

    const findingsA = run("K1", serverA).filter(f => f.rule_id === "K1");
    const findingsB = run("K1", serverB).filter(f => f.rule_id === "K1");

    // Both must detect the console.log("request handling...") pattern
    expect(findingsA.length).toBeGreaterThanOrEqual(1);
    expect(findingsB.length).toBeGreaterThanOrEqual(1);

    const confA = findingsA[0].confidence;
    const confB = findingsB[0].confidence;

    // Server A gets boosted by: user_input_confirmed (+0.10), handler_code (+0.08),
    // no_nearby_mitigation (+0.08), network_exposed_no_auth (+0.10)
    // Server B gets penalized by: static_value_only (-0.10), setup_config_code (-0.08),
    // local_only_transport (-0.08)
    // The gap must be meaningful — at least 0.15
    expect(confA).toBeGreaterThan(confB);
    expect(confA - confB).toBeGreaterThanOrEqual(0.15);
  });

  it("confidence is NOT the old hardcoded 0.75", () => {
    const server = ctx({
      server: { id: "test-srv", name: "test-server", description: "Test", github_url: null },
      source_code: `
function handleRequest(req) {
  console.log("request handling", req.body);
}
`,
    });

    const findings = run("K1", server).filter(f => f.rule_id === "K1");
    expect(findings.length).toBeGreaterThanOrEqual(1);

    // The old hardcoded confidence was exactly 0.75.
    // Dynamic chain.confidence should differ because computeConfidence() starts
    // at base 0.70 (source+propagation+sink), adds structural_match (-0.05),
    // then 5 server-specific signals. The result cannot land on exactly 0.75.
    expect(findings[0].confidence).not.toBeCloseTo(0.75, 2);
  });

  it("evidence_chain exists with >= 4 confidence_factors", () => {
    const server = ctx({
      server: { id: "test", name: "test-server", description: "Test", github_url: null },
      tools: [
        { name: "execute_command", description: "Run a shell command", input_schema: { type: "object" } },
      ],
      source_code: `
async function handleTool(req, res) {
  console.log("request handling", req.body.action);
  await runCommand(req.body.command);
}
`,
      connection_metadata: { auth_required: false, transport: "sse", response_time_ms: 50 },
    });

    const findings = run("K1", server).filter(f => f.rule_id === "K1");
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const chain = findings[0].metadata?.evidence_chain as {
      confidence: number;
      confidence_factors: Array<{ factor: string; adjustment: number; rationale: string }>;
    } | undefined;

    expect(chain).toBeDefined();
    // structural_match (-0.05) + 5 signals = at least 6 factors,
    // but some signals may collapse to 0 adjustment. Require >= 4.
    expect(chain!.confidence_factors.length).toBeGreaterThanOrEqual(4);

    // Each factor must have the three required fields
    for (const factor of chain!.confidence_factors) {
      expect(typeof factor.factor).toBe("string");
      expect(factor.factor.length).toBeGreaterThan(0);
      expect(typeof factor.adjustment).toBe("number");
      expect(typeof factor.rationale).toBe("string");
      expect(factor.rationale.length).toBeGreaterThan(0);
    }
  });

  it("chain.confidence matches finding.confidence exactly", () => {
    const server = ctx({
      server: { id: "exact", name: "exact-test", description: "Test", github_url: null },
      source_code: `
async function handleTool(req, res) {
  console.log("processing request", req.body);
}
`,
      connection_metadata: { auth_required: false, transport: "sse", response_time_ms: 50 },
    });

    const findings = run("K1", server).filter(f => f.rule_id === "K1");
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const chain = findings[0].metadata?.evidence_chain as { confidence: number } | undefined;
    expect(chain).toBeDefined();

    // The finding's confidence field must be set FROM the chain, not independently.
    // compliance-remaining-detector.ts line 123: `confidence: chain.confidence`
    expect(chain!.confidence).toBe(findings[0].confidence);
  });
});
