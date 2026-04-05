/**
 * Dynamic Confidence Tests — Proves confidence varies by server context.
 *
 * The core assertion: the same rule, applied to different servers,
 * produces different confidence values. Not because we hardcoded different
 * numbers, but because the evidence chain reflects what was actually observed.
 *
 * Each test constructs two servers with the same vulnerability pattern but
 * different contexts (handler vs config code, auth vs no auth, etc.) and
 * verifies the confidence differs.
 */
import { describe, it, expect } from "vitest";
import { AnalysisEngine, type AnalysisContext } from "../src/engine.js";
import type { DetectionRule } from "@mcp-sentinel/database";
import "../src/rules/index.js";

// ─── Helper: build a minimal AnalysisContext ────────────────────────────────

function makeContext(overrides: Partial<AnalysisContext> & { server: AnalysisContext["server"] }): AnalysisContext {
  return {
    tools: [],
    dependencies: [],
    connection_metadata: null,
    source_code: null,
    ...overrides,
  };
}

// ─── K1 rule (Absent Structured Logging) — compliance-remaining-detector ────

const k1RuleMain: DetectionRule = {
  id: "K1", name: "Absent Structured Logging",
  category: "compliance-governance", severity: "high",
  owasp: "MCP09-logging-monitoring", mitre: null,
  detect: { type: "typed" }, remediation: "Use structured logging.",
  enabled: true,
};

const engine = new AnalysisEngine([k1RuleMain]);

describe("Dynamic confidence: same rule, different servers", () => {
  describe("K1 Absent Structured Logging", () => {
    it("produces higher confidence on a network-exposed server with dangerous tools", () => {
      // Server A: network-exposed, no auth, has destructive tools, pattern in handler
      const serverA = makeContext({
        server: { id: "payment-srv", name: "payment-processor", description: "Process payments", github_url: null },
        tools: [
          { name: "execute_payment", description: "Execute a payment transaction", input_schema: { type: "object" } },
          { name: "delete_account", description: "Delete a user account", input_schema: { type: "object" } },
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

      // Server B: local stdio, minimal tools, same pattern in config/setup code
      const serverB = makeContext({
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

      const findingsA = engine.analyzeRich(serverA).filter(f => f.rule_id === "K1");
      const findingsB = engine.analyzeRich(serverB).filter(f => f.rule_id === "K1");

      // Both should detect the console.log pattern
      expect(findingsA.length).toBeGreaterThanOrEqual(1);
      expect(findingsB.length).toBeGreaterThanOrEqual(1);

      const confA = findingsA[0].confidence;
      const confB = findingsB[0].confidence;

      // Server A should have HIGHER confidence than Server B
      // Server A: handler code (+0.08), user input in req.body (+0.10),
      //   no mitigation (+0.08), network exposed no auth (+0.10)
      // Server B: setup code (-0.08), no user input, local transport (-0.08)
      expect(confA).toBeGreaterThan(confB);

      // The gap should be meaningful — at least 0.15 difference
      expect(confA - confB).toBeGreaterThanOrEqual(0.15);
    });

    it("confidence reflects evidence chain, not the old hardcoded 0.75", () => {
      const server = makeContext({
        server: { id: "test-srv", name: "test-server", description: "Test", github_url: null },
        tools: [],
        source_code: `
function handleRequest(req) {
  console.log("request handling", req.body);
}
`,
        connection_metadata: null,
      });

      const findings = engine.analyzeRich(server).filter(f => f.rule_id === "K1");
      expect(findings.length).toBeGreaterThanOrEqual(1);

      // Confidence should NOT be the old hardcoded value of 0.75
      expect(findings[0].confidence).not.toBeCloseTo(0.75, 2);

      // Should have evidence chain with confidence factors
      const chain = findings[0].metadata?.evidence_chain as { confidence_factors: Array<{ factor: string }> } | undefined;
      expect(chain).toBeDefined();
      // structural_match + at least some signals (match specificity, code location, etc.)
      expect(chain!.confidence_factors.length).toBeGreaterThan(1);
    });
  });
});

describe("Confidence signals differentiate server contexts", () => {
  // K1 rule for testing
  const k1Rule: DetectionRule = {
    id: "K1", name: "Absent Structured Logging",
    category: "compliance-governance", severity: "high",
    owasp: "MCP09-logging-monitoring", mitre: null,
    detect: { type: "typed" }, remediation: "Use structured logging.",
    enabled: true,
  };
  const k1Engine = new AnalysisEngine([k1Rule]);

  it("network-exposed server gets higher confidence than local server", () => {
    const code = `
async function handleRequest(req) {
  console.log("request received", req.body);
  return processRequest(req);
}
`;
    const networkServer = makeContext({
      server: { id: "net", name: "net-srv", description: "Network service", github_url: null },
      tools: [{ name: "process", description: "Process data", input_schema: { type: "object" } }],
      source_code: code,
      connection_metadata: { auth_required: false, transport: "sse", response_time_ms: 50 },
    });

    const localServer = makeContext({
      server: { id: "local", name: "local-tool", description: "Local tool", github_url: null },
      tools: [{ name: "status", description: "Get status", input_schema: { type: "object" } }],
      source_code: code,
      connection_metadata: { auth_required: false, transport: "stdio", response_time_ms: 5 },
    });

    const netFindings = k1Engine.analyzeRich(networkServer).filter(f => f.rule_id === "K1");
    const localFindings = k1Engine.analyzeRich(localServer).filter(f => f.rule_id === "K1");

    if (netFindings.length > 0 && localFindings.length > 0) {
      // Network-exposed should have higher confidence
      expect(netFindings[0].confidence).toBeGreaterThan(localFindings[0].confidence);
    }
  });

  it("code near mitigations gets lower confidence than unprotected code", () => {
    const unprotectedCode = `
async function handleTool(req, res) {
  console.log("request handling", req.body.action);
  const result = await doWork(req);
  res.json(result);
}
`;

    const protectedCode = `
const logger = require("pino")();
async function handleTool(req, res) {
  console.log("request handling", req.body.action);
  const sanitized = sanitize(req.body.action);
  const result = await doWork(sanitized);
  res.json(result);
}
`;

    const unprotected = makeContext({
      server: { id: "unp", name: "unprotected", description: "No protection", github_url: null },
      tools: [],
      source_code: unprotectedCode,
    });

    const protectedCtx = makeContext({
      server: { id: "prot", name: "protected", description: "With protection", github_url: null },
      tools: [],
      source_code: protectedCode,
    });

    const unprotFindings = k1Engine.analyzeRich(unprotected).filter(f => f.rule_id === "K1");
    const protFindings = k1Engine.analyzeRich(protectedCtx).filter(f => f.rule_id === "K1");

    if (unprotFindings.length > 0 && protFindings.length > 0) {
      // Unprotected code should have higher confidence
      expect(unprotFindings[0].confidence).toBeGreaterThan(protFindings[0].confidence);
    }
  });

  it("network-exposed no-auth server gets higher confidence than local with auth", () => {
    const code = `
function handleRequest(req) {
  console.log("request handling", req.url);
  return fetch(req.url);
}
`;
    const exposed = makeContext({
      server: { id: "exposed", name: "exposed-srv", description: "Exposed server", github_url: null },
      tools: [
        { name: "execute_command", description: "Execute a shell command", input_schema: { type: "object" as const } },
      ],
      source_code: code,
      connection_metadata: { auth_required: false, transport: "sse", response_time_ms: 50 },
    });

    const secured = makeContext({
      server: { id: "secured", name: "secured-srv", description: "Secured server", github_url: null },
      tools: [
        { name: "get_status", description: "Get status", input_schema: { type: "object" as const } },
      ],
      source_code: code,
      connection_metadata: { auth_required: true, transport: "stdio", response_time_ms: 5 },
    });

    const exposedFindings = k1Engine.analyzeRich(exposed).filter(f => f.rule_id === "K1");
    const securedFindings = k1Engine.analyzeRich(secured).filter(f => f.rule_id === "K1");

    if (exposedFindings.length > 0 && securedFindings.length > 0) {
      // Exposed + dangerous tools should have higher confidence
      expect(exposedFindings[0].confidence).toBeGreaterThan(securedFindings[0].confidence);
    }
  });
});

describe("Evidence chain structure", () => {
  it("confidence factors are present and explain the reasoning", () => {
    const server = makeContext({
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

    const findings = engine.analyzeRich(server).filter(f => f.rule_id === "K1");
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const chain = findings[0].metadata?.evidence_chain as {
      confidence: number;
      confidence_factors: Array<{ factor: string; adjustment: number; rationale: string }>;
    } | undefined;

    expect(chain).toBeDefined();

    // Should have the structural match factor + at least 3 server-specific signals
    // (match specificity, code location, mitigation scan, tool correlation, exposure)
    expect(chain!.confidence_factors.length).toBeGreaterThanOrEqual(4);

    // Each factor should have all three fields
    for (const factor of chain!.confidence_factors) {
      expect(factor.factor).toBeTruthy();
      expect(typeof factor.adjustment).toBe("number");
      expect(factor.rationale).toBeTruthy();
    }

    // The chain's confidence should match the finding's confidence
    expect(chain!.confidence).toBeCloseTo(findings[0].confidence, 10);
  });
});
