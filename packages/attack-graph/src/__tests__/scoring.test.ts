/**
 * Scoring Tests — 7-Factor Exploitability Model
 *
 * Tests verify:
 *   1. Each factor computes correctly in isolation
 *   2. Boundary values at rating thresholds
 *   3. Composite scoring with known inputs
 *   4. Edge cases (empty inputs, null scores, missing data)
 *   5. Weight sum invariant (must equal 1.0)
 */
import { describe, it, expect } from "vitest";
import {
  computeHopCount,
  computeCapabilityConfidence,
  computeServerScoreWeakness,
  computeRealWorldPrecedent,
  computeInjectionGatewayPresent,
  computeSupportingFindings,
  computeEdgeSeverity,
  computeExploitability,
  scoreToRating,
} from "../scoring.js";
import type {
  AttackStep,
  CapabilityNode,
  RiskEdge,
  KillChainTemplate,
} from "../types.js";

// ── Test helpers ───────────────────────────────────────────────────────────────

function makeStep(overrides: Partial<AttackStep> = {}): AttackStep {
  return {
    ordinal: 1,
    server_id: "srv-1",
    server_name: "test-server",
    role: "data_source",
    capabilities_used: ["reads-data"],
    tools_involved: [],
    edge_to_next: null,
    narrative: "",
    ...overrides,
  };
}

function makeNode(overrides: Partial<CapabilityNode> = {}): CapabilityNode {
  return {
    server_id: "srv-1",
    server_name: "test-server",
    server_slug: "test-server",
    latest_score: 50,
    capabilities: ["reads-data"],
    is_injection_gateway: false,
    is_shared_writer: false,
    category: null,
    ...overrides,
  };
}

function makeEdge(overrides: Partial<RiskEdge> = {}): RiskEdge {
  return {
    from_server_id: "srv-1",
    to_server_id: "srv-2",
    edge_type: "data_flow",
    severity: "high",
    description: "test edge",
    owasp: "MCP04",
    mitre: "AML.T0057",
    ...overrides,
  };
}

function makeTemplate(overrides: Partial<KillChainTemplate> = {}): KillChainTemplate {
  return {
    id: "KC-TEST",
    name: "Test Template",
    objective: "data_exfiltration",
    precedent: "Test precedent (2025).",
    min_servers: 2,
    roles: [],
    required_patterns: [],
    required_edge_types: [],
    base_likelihood: 0.7,
    base_impact: 0.8,
    owasp: ["MCP04"],
    mitre: ["AML.T0057"],
    ...overrides,
  };
}

// ── Weight invariant ───────────────────────────────────────────────────────────

describe("weight invariant", () => {
  it("all factor weights sum to exactly 1.0", () => {
    const template = makeTemplate();
    const steps = [makeStep(), makeStep({ ordinal: 2, server_id: "srv-2" })];
    const nodes = [makeNode(), makeNode({ server_id: "srv-2" })];
    const edges = [makeEdge()];

    const result = computeExploitability({ steps, template, nodes, edges });

    const weightSum = result.factors.reduce((sum, f) => sum + f.weight, 0);
    expect(weightSum).toBeCloseTo(1.0, 10);
  });

  it("exactly 7 factors are produced", () => {
    const result = computeExploitability({
      steps: [makeStep()],
      template: makeTemplate(),
      nodes: [makeNode()],
      edges: [],
    });
    expect(result.factors).toHaveLength(7);
  });
});

// ── Factor 1: Hop Count ────────────────────────────────────────────────────────

describe("computeHopCount", () => {
  it("2-step chain scores 1.0", () => {
    const steps = [makeStep({ ordinal: 1 }), makeStep({ ordinal: 2 })];
    expect(computeHopCount(steps).value).toBe(1.0);
  });

  it("single step scores 1.0", () => {
    expect(computeHopCount([makeStep()]).value).toBe(1.0);
  });

  it("3-step chain scores 0.8", () => {
    const steps = [
      makeStep({ ordinal: 1 }),
      makeStep({ ordinal: 2 }),
      makeStep({ ordinal: 3 }),
    ];
    expect(computeHopCount(steps).value).toBe(0.8);
  });

  it("4-step chain scores 0.6", () => {
    const steps = Array.from({ length: 4 }, (_, i) => makeStep({ ordinal: i + 1 }));
    expect(computeHopCount(steps).value).toBe(0.6);
  });

  it("10-step chain still scores 0.6 (floor)", () => {
    const steps = Array.from({ length: 10 }, (_, i) => makeStep({ ordinal: i + 1 }));
    expect(computeHopCount(steps).value).toBe(0.6);
  });
});

// ── Factor 2: Capability Confidence ────────────────────────────────────────────

describe("computeCapabilityConfidence", () => {
  it("3+ capabilities per step scores 1.0", () => {
    const steps = [
      makeStep({ capabilities_used: ["reads-data", "accesses-filesystem", "manages-credentials"] }),
    ];
    expect(computeCapabilityConfidence(steps).value).toBe(1.0);
  });

  it("2 capabilities per step scores 0.8", () => {
    const steps = [
      makeStep({ capabilities_used: ["reads-data", "accesses-filesystem"] }),
    ];
    expect(computeCapabilityConfidence(steps).value).toBe(0.8);
  });

  it("1 capability per step scores 0.6", () => {
    const steps = [makeStep({ capabilities_used: ["reads-data"] })];
    expect(computeCapabilityConfidence(steps).value).toBe(0.6);
  });

  it("averages across multiple steps", () => {
    const steps = [
      makeStep({ capabilities_used: ["reads-data", "accesses-filesystem", "manages-credentials"] }), // 1.0
      makeStep({ capabilities_used: ["sends-network"] }), // 0.6
    ];
    // average = (1.0 + 0.6) / 2 = 0.8
    expect(computeCapabilityConfidence(steps).value).toBe(0.8);
  });

  it("empty steps returns default 0.7", () => {
    expect(computeCapabilityConfidence([]).value).toBe(0.7);
  });
});

// ── Factor 3: Server Score Weakness ────────────────────────────────────────────

describe("computeServerScoreWeakness", () => {
  it("score < 40 maps to 1.0 (critical)", () => {
    const nodes = [makeNode({ latest_score: 25 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(1.0);
  });

  it("score 39 maps to 1.0 (boundary)", () => {
    const nodes = [makeNode({ latest_score: 39 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(1.0);
  });

  it("score 40 maps to 0.8 (poor)", () => {
    const nodes = [makeNode({ latest_score: 40 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.8);
  });

  it("score 59 maps to 0.8 (boundary)", () => {
    const nodes = [makeNode({ latest_score: 59 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.8);
  });

  it("score 60 maps to 0.5 (moderate)", () => {
    const nodes = [makeNode({ latest_score: 60 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.5);
  });

  it("score 80 maps to 0.2 (good)", () => {
    const nodes = [makeNode({ latest_score: 80 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.2);
  });

  it("score 100 maps to 0.2 (good)", () => {
    const nodes = [makeNode({ latest_score: 100 })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.2);
  });

  it("null score maps to 0.7 (conservative unknown)", () => {
    const nodes = [makeNode({ latest_score: null })];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.7);
  });

  it("picks the weakest server (min score)", () => {
    const nodes = [
      makeNode({ server_id: "a", latest_score: 80 }),
      makeNode({ server_id: "b", latest_score: 30 }),
      makeNode({ server_id: "c", latest_score: 65 }),
    ];
    // min = 30 → 1.0
    expect(computeServerScoreWeakness(nodes).value).toBe(1.0);
  });

  it("ignores null scores when real scores exist", () => {
    const nodes = [
      makeNode({ server_id: "a", latest_score: 75 }),
      makeNode({ server_id: "b", latest_score: null }),
    ];
    // min of non-null = 75 → 0.5
    expect(computeServerScoreWeakness(nodes).value).toBe(0.5);
  });

  it("all null scores returns 0.7", () => {
    const nodes = [
      makeNode({ server_id: "a", latest_score: null }),
      makeNode({ server_id: "b", latest_score: null }),
    ];
    expect(computeServerScoreWeakness(nodes).value).toBe(0.7);
  });

  it("empty nodes returns 0.7", () => {
    expect(computeServerScoreWeakness([]).value).toBe(0.7);
  });
});

// ── Factor 4: Real-World Precedent ─────────────────────────────────────────────

describe("computeRealWorldPrecedent", () => {
  it("CVE in precedent scores 1.0", () => {
    const template = makeTemplate({
      precedent: "CVE-2025-54135: .cursorrules injection",
    });
    expect(computeRealWorldPrecedent(template).value).toBe(1.0);
  });

  it("research paper precedent scores 0.8", () => {
    const template = makeTemplate({
      precedent: "Invariant Labs (2025): vector store injection via MCP.",
    });
    expect(computeRealWorldPrecedent(template).value).toBe(0.8);
  });

  it("empty precedent scores 0.5", () => {
    const template = makeTemplate({ precedent: "" });
    expect(computeRealWorldPrecedent(template).value).toBe(0.5);
  });

  it("detects CVE pattern case-insensitively", () => {
    const template = makeTemplate({
      precedent: "Based on cve-2024-12345 research",
    });
    expect(computeRealWorldPrecedent(template).value).toBe(1.0);
  });
});

// ── Factor 5: Injection Gateway Present ────────────────────────────────────────

describe("computeInjectionGatewayPresent", () => {
  it("confirmed gateway scores 1.0", () => {
    const steps = [makeStep({ role: "injection_gateway", server_id: "gw-1" })];
    const nodes = [makeNode({ server_id: "gw-1", is_injection_gateway: true })];
    expect(computeInjectionGatewayPresent(steps, nodes).value).toBe(1.0);
  });

  it("unconfirmed gateway role scores 0.6", () => {
    const steps = [makeStep({ role: "injection_gateway", server_id: "gw-1" })];
    const nodes = [makeNode({ server_id: "gw-1", is_injection_gateway: false })];
    expect(computeInjectionGatewayPresent(steps, nodes).value).toBe(0.6);
  });

  it("no gateway role scores 0.3", () => {
    const steps = [makeStep({ role: "data_source" })];
    const nodes = [makeNode()];
    expect(computeInjectionGatewayPresent(steps, nodes).value).toBe(0.3);
  });

  it("gateway role but node not in node list scores 0.6", () => {
    const steps = [makeStep({ role: "injection_gateway", server_id: "missing" })];
    const nodes = [makeNode({ server_id: "other" })];
    // gatewayNode is undefined, so is_injection_gateway check fails → 0.6
    expect(computeInjectionGatewayPresent(steps, nodes).value).toBe(0.6);
  });
});

// ── Factor 6: Supporting Findings ──────────────────────────────────────────────

describe("computeSupportingFindings", () => {
  it("3+ findings scores 1.0", () => {
    const findings = { "srv-1": ["F1", "G1", "C1"] };
    expect(computeSupportingFindings(findings, ["srv-1"]).value).toBe(1.0);
  });

  it("1-2 findings scores 0.7", () => {
    const findings = { "srv-1": ["F1"] };
    expect(computeSupportingFindings(findings, ["srv-1"]).value).toBe(0.7);
  });

  it("0 findings scores 0.3", () => {
    const findings = { "srv-1": [] };
    expect(computeSupportingFindings(findings, ["srv-1"]).value).toBe(0.3);
  });

  it("undefined serverFindings scores 0.3", () => {
    expect(computeSupportingFindings(undefined, ["srv-1"]).value).toBe(0.3);
  });

  it("aggregates findings across multiple servers", () => {
    const findings = {
      "srv-1": ["F1"],
      "srv-2": ["G1", "C1"],
    };
    // total = 3 → 1.0
    expect(computeSupportingFindings(findings, ["srv-1", "srv-2"]).value).toBe(1.0);
  });

  it("ignores findings from non-participating servers", () => {
    const findings = {
      "srv-1": ["F1"],
      "srv-other": ["G1", "C1", "A1", "B1"],
    };
    // only srv-1 participates → 1 finding → 0.7
    expect(computeSupportingFindings(findings, ["srv-1"]).value).toBe(0.7);
  });
});

// ── Factor 7: Edge Severity ────────────────────────────────────────────────────

describe("computeEdgeSeverity", () => {
  it("all critical edges score 1.0", () => {
    const edges = [
      makeEdge({ severity: "critical" }),
      makeEdge({ severity: "critical" }),
    ];
    expect(computeEdgeSeverity(edges).value).toBe(1.0);
  });

  it("all low edges score 0.25", () => {
    const edges = [makeEdge({ severity: "low" }), makeEdge({ severity: "low" })];
    expect(computeEdgeSeverity(edges).value).toBe(0.25);
  });

  it("mixed edges average correctly", () => {
    const edges = [
      makeEdge({ severity: "critical" }),  // 1.0
      makeEdge({ severity: "low" }),       // 0.25
    ];
    // avg = (1.0 + 0.25) / 2 = 0.625
    expect(computeEdgeSeverity(edges).value).toBe(0.63); // rounded to 2 dec
  });

  it("empty edges returns default 0.5", () => {
    expect(computeEdgeSeverity([]).value).toBe(0.5);
  });

  it("single medium edge scores 0.5", () => {
    expect(computeEdgeSeverity([makeEdge({ severity: "medium" })]).value).toBe(0.5);
  });
});

// ── Rating thresholds ──────────────────────────────────────────────────────────

describe("scoreToRating", () => {
  it("0.75 → critical (boundary)", () => {
    expect(scoreToRating(0.75)).toBe("critical");
  });

  it("0.749 → high (just below boundary)", () => {
    expect(scoreToRating(0.749)).toBe("high");
  });

  it("0.55 → high (boundary)", () => {
    expect(scoreToRating(0.55)).toBe("high");
  });

  it("0.549 → medium (just below)", () => {
    expect(scoreToRating(0.549)).toBe("medium");
  });

  it("0.35 → medium (boundary)", () => {
    expect(scoreToRating(0.35)).toBe("medium");
  });

  it("0.349 → low (just below)", () => {
    expect(scoreToRating(0.349)).toBe("low");
  });

  it("0.0 → low", () => {
    expect(scoreToRating(0.0)).toBe("low");
  });

  it("1.0 → critical", () => {
    expect(scoreToRating(1.0)).toBe("critical");
  });
});

// ── Composite: computeExploitability ───────────────────────────────────────────

describe("computeExploitability", () => {
  it("overall score is clamped to [0.0, 1.0]", () => {
    const result = computeExploitability({
      steps: [makeStep(), makeStep({ ordinal: 2, server_id: "srv-2" })],
      template: makeTemplate(),
      nodes: [makeNode(), makeNode({ server_id: "srv-2" })],
      edges: [makeEdge({ severity: "critical" })],
      serverFindings: { "srv-1": ["F1", "G1", "C1"], "srv-2": ["A1"] },
    });
    expect(result.overall).toBeGreaterThanOrEqual(0.0);
    expect(result.overall).toBeLessThanOrEqual(1.0);
  });

  it("high-risk config produces critical or high rating", () => {
    const result = computeExploitability({
      steps: [
        makeStep({
          ordinal: 1,
          server_id: "gw",
          role: "injection_gateway",
          capabilities_used: ["web-scraping", "reads-messages"],
        }),
        makeStep({
          ordinal: 2,
          server_id: "fs",
          role: "data_source",
          capabilities_used: ["reads-data", "accesses-filesystem", "manages-credentials"],
        }),
        makeStep({
          ordinal: 3,
          server_id: "net",
          role: "exfiltrator",
          capabilities_used: ["sends-network"],
        }),
      ],
      template: makeTemplate({
        precedent: "CVE-2025-54135: real attack",
        base_likelihood: 0.85,
        base_impact: 0.90,
      }),
      nodes: [
        makeNode({ server_id: "gw", is_injection_gateway: true, latest_score: 25 }),
        makeNode({ server_id: "fs", latest_score: 35 }),
        makeNode({ server_id: "net", latest_score: 45 }),
      ],
      edges: [
        makeEdge({ severity: "critical", from_server_id: "gw", to_server_id: "fs" }),
        makeEdge({ severity: "critical", from_server_id: "fs", to_server_id: "net" }),
      ],
      serverFindings: { gw: ["G1", "A1"], fs: ["F1", "C5"], net: ["F3"] },
    });

    // With all factors favorable, should be high or critical
    expect(["critical", "high"]).toContain(result.rating);
    expect(result.overall).toBeGreaterThan(0.55);
  });

  it("low-risk config produces low or medium rating", () => {
    const result = computeExploitability({
      steps: [
        makeStep({ ordinal: 1, capabilities_used: ["reads-data"] }),
        makeStep({ ordinal: 2, server_id: "srv-2", capabilities_used: ["writes-data"] }),
        makeStep({ ordinal: 3, server_id: "srv-3", capabilities_used: ["sends-network"] }),
        makeStep({ ordinal: 4, server_id: "srv-4", capabilities_used: ["reads-data"] }),
      ],
      template: makeTemplate({
        precedent: "",
        base_likelihood: 0.3,
        base_impact: 0.4,
      }),
      nodes: [
        makeNode({ latest_score: 90 }),
        makeNode({ server_id: "srv-2", latest_score: 85 }),
        makeNode({ server_id: "srv-3", latest_score: 88 }),
        makeNode({ server_id: "srv-4", latest_score: 92 }),
      ],
      edges: [makeEdge({ severity: "low" })],
    });

    expect(["low", "medium"]).toContain(result.rating);
    expect(result.overall).toBeLessThan(0.55);
  });

  it("likelihood, impact, effort are all in [0.0, 1.0]", () => {
    const result = computeExploitability({
      steps: [makeStep()],
      template: makeTemplate(),
      nodes: [makeNode()],
      edges: [makeEdge()],
    });

    expect(result.likelihood).toBeGreaterThanOrEqual(0.0);
    expect(result.likelihood).toBeLessThanOrEqual(1.0);
    expect(result.impact).toBeGreaterThanOrEqual(0.0);
    expect(result.impact).toBeLessThanOrEqual(1.0);
    expect(result.effort).toBeGreaterThanOrEqual(0.0);
    expect(result.effort).toBeLessThanOrEqual(1.0);
  });

  it("overall score is deterministic (same inputs → same output)", () => {
    const input = {
      steps: [makeStep(), makeStep({ ordinal: 2, server_id: "srv-2" })],
      template: makeTemplate(),
      nodes: [makeNode(), makeNode({ server_id: "srv-2" })],
      edges: [makeEdge()],
    };

    const result1 = computeExploitability(input);
    const result2 = computeExploitability(input);

    expect(result1.overall).toBe(result2.overall);
    expect(result1.rating).toBe(result2.rating);
    expect(result1.factors.map((f) => f.value)).toEqual(
      result2.factors.map((f) => f.value)
    );
  });

  it("each factor has correct weight assigned", () => {
    const result = computeExploitability({
      steps: [makeStep()],
      template: makeTemplate(),
      nodes: [makeNode()],
      edges: [],
    });

    const expectedWeights: Record<string, number> = {
      hop_count: 0.15,
      capability_confidence: 0.20,
      server_score_weakness: 0.15,
      real_world_precedent: 0.15,
      injection_gateway_present: 0.10,
      supporting_findings: 0.10,
      edge_severity: 0.15,
    };

    for (const factor of result.factors) {
      expect(factor.weight).toBe(expectedWeights[factor.factor]);
    }
  });
});

// ── Kill chain template validation ─────────────────────────────────────────────

describe("kill chain template structure", () => {
  // Import the actual templates to validate structure
  it("all templates have required fields", async () => {
    const { ALL_KILL_CHAINS } = await import("../kill-chains.js");

    for (const kc of ALL_KILL_CHAINS) {
      expect(kc.id).toMatch(/^KC0[1-7]$/);
      expect(kc.name.length).toBeGreaterThan(0);
      expect(kc.objective.length).toBeGreaterThan(0);
      expect(kc.precedent.length).toBeGreaterThan(0);
      expect(kc.min_servers).toBeGreaterThanOrEqual(2);
      expect(kc.roles.length).toBeGreaterThanOrEqual(2);
      expect(kc.required_patterns.length).toBeGreaterThan(0);
      expect(kc.required_edge_types.length).toBeGreaterThan(0);
      expect(kc.base_likelihood).toBeGreaterThan(0);
      expect(kc.base_likelihood).toBeLessThanOrEqual(1);
      expect(kc.base_impact).toBeGreaterThan(0);
      expect(kc.base_impact).toBeLessThanOrEqual(1);
      expect(kc.owasp.length).toBeGreaterThan(0);
      expect(kc.mitre.length).toBeGreaterThan(0);
    }
  });

  it("all templates have unique IDs", async () => {
    const { ALL_KILL_CHAINS } = await import("../kill-chains.js");
    const ids = ALL_KILL_CHAINS.map((kc) => kc.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("role capability requirements are non-empty", async () => {
    const { ALL_KILL_CHAINS } = await import("../kill-chains.js");

    for (const kc of ALL_KILL_CHAINS) {
      for (const role of kc.roles) {
        expect(role.required_capabilities.length).toBeGreaterThan(0);
        for (const capGroup of role.required_capabilities) {
          expect(capGroup.length).toBeGreaterThan(0);
        }
      }
    }
  });

  it("min_servers <= number of roles", async () => {
    const { ALL_KILL_CHAINS } = await import("../kill-chains.js");

    for (const kc of ALL_KILL_CHAINS) {
      expect(kc.min_servers).toBeLessThanOrEqual(kc.roles.length);
    }
  });

  it("hasRequiredPatterns returns true when at least one pattern matches", async () => {
    const { hasRequiredPatterns, KC01 } = await import("../kill-chains.js");
    // KC01 requires P01, P03, or P09
    expect(hasRequiredPatterns(KC01, ["P01"])).toBe(true);
    expect(hasRequiredPatterns(KC01, ["P03"])).toBe(true);
    expect(hasRequiredPatterns(KC01, ["P09"])).toBe(true);
    expect(hasRequiredPatterns(KC01, ["P02"])).toBe(false);
    expect(hasRequiredPatterns(KC01, [])).toBe(false);
  });

  it("hasRequiredEdgeTypes requires ALL edge types present", async () => {
    const { hasRequiredEdgeTypes, KC01 } = await import("../kill-chains.js");
    // KC01 requires injection_path AND exfiltration_chain
    expect(
      hasRequiredEdgeTypes(KC01, [
        { edge_type: "injection_path" },
        { edge_type: "exfiltration_chain" },
      ])
    ).toBe(true);
    expect(
      hasRequiredEdgeTypes(KC01, [{ edge_type: "injection_path" }])
    ).toBe(false);
    expect(hasRequiredEdgeTypes(KC01, [])).toBe(false);
  });
});
