// @vitest-environment jsdom
/**
 * EvidenceChainViz Critical Test Suite
 *
 * Tests the regulator-grade 5-question EvidenceChainViz component which:
 * - Takes { chain: EvidenceChainData | null | undefined, confidence?: number }
 * - Uses discriminated union link types (SourceLink, PropagationLink, etc.)
 * - 5-section layout: What Was Found, Where in the Code, Why This Is Dangerous,
 *   Confidence Assessment, How to Verify
 * - CSS prefix: ec5- (not ec-)
 * - Badges: ENTRY (source), FLOW (propagation), DANGER (sink)
 * - confLevel thresholds: >=0.70 high, >=0.45 medium, <0.45 low
 * - Confidence display: Math.round(confidence * 100) — NO clamping
 * - Truncation: 100 chars in WhatSection prose, 80 chars in WhereSection flow nodes
 * - Factor names: underscores replaced with spaces (f.factor.replace(/_/g, " "))
 * - Source/sink types rendered as lowercase prose labels from label maps
 * - Mitigations: ✓ (present) / ✗ (absent) with mitigation_type (dashes→spaces)
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import EvidenceChainViz, { type EvidenceChainData } from "../components/EvidenceChainViz";

// ── Fixtures ────────────────────────────────────────────────────────────────────

function makeChain(overrides: Partial<EvidenceChainData> = {}): EvidenceChainData {
  return {
    links: [
      {
        type: "source",
        source_type: "user-parameter",
        location: "src/handler.ts:42",
        observed: "req.body.input passed to exec()",
        rationale: "User-controlled input flows to command execution",
      },
      {
        type: "propagation",
        propagation_type: "variable-assignment",
        location: "src/handler.ts:45",
        observed: "const cmd = input",
      },
      {
        type: "sink",
        sink_type: "command-execution",
        location: "src/handler.ts:48",
        observed: "exec(cmd)",
      },
    ],
    confidence: 0.92,
    confidence_factors: [
      { factor: "ast_taint", adjustment: 0.15, rationale: "AST-confirmed taint flow" },
      { factor: "hop_count", adjustment: -0.10, rationale: "2-hop propagation" },
    ],
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════════
// Null/undefined handling
// ═════════════════════════════════════════════════════════════════════════════════

describe("null/undefined handling", () => {
  it("chain=null, confidence=undefined → renders nothing (null)", () => {
    const { container } = render(
      <EvidenceChainViz chain={null} />
    );
    expect(container.innerHTML).toBe("");
  });

  it("chain=null, confidence=null → renders nothing (null)", () => {
    const { container } = render(
      <EvidenceChainViz chain={null} confidence={undefined} />
    );
    expect(container.innerHTML).toBe("");
  });

  it("chain=undefined, confidence=0.85 → renders minimal confidence bar only", () => {
    const { container } = render(
      <EvidenceChainViz chain={undefined} confidence={0.85} />
    );
    expect(container.textContent).toContain("85%");
    expect(container.textContent).toContain("Confidence");
    // Should NOT render full chain report
    expect(container.querySelector(".ec5-report")).toBeNull();
    expect(container.querySelector(".ec5-confidence-only")).not.toBeNull();
  });

  it("chain=null, confidence=0 → renders '0%' (0 is valid, not null)", () => {
    const { container } = render(
      <EvidenceChainViz chain={null} confidence={0} />
    );
    expect(container.textContent).toContain("0%");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence display
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence display", () => {
  it("confidence=0.0 → '0%'", () => {
    const chain = makeChain({ confidence: 0.0 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("0%");
  });

  it("confidence=1.0 → '100%'", () => {
    const chain = makeChain({ confidence: 1.0 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("100%");
  });

  it("confidence=0.5 → '50%'", () => {
    const chain = makeChain({ confidence: 0.5 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("50%");
  });

  it("confidence=1.5 → '150%' (NO clamping in this version)", () => {
    const chain = makeChain({ confidence: 1.5 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Math.round(1.5 * 100) = 150 — this component does NOT clamp
    expect(container.textContent).toContain("150%");
  });

  it("confidence=-0.3 → '-30%' (NO clamping)", () => {
    const chain = makeChain({ confidence: -0.3 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("-30%");
  });

  it("confidence=NaN → 'NaN%'", () => {
    const chain = makeChain({ confidence: NaN });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("NaN%");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence levels (confLevel thresholds)
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence levels", () => {
  it("confidence=0.70 → 'high' class", () => {
    const chain = makeChain({ confidence: 0.70 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-conf-high")).not.toBeNull();
  });

  it("confidence=0.69 → 'medium' class", () => {
    const chain = makeChain({ confidence: 0.69 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-conf-medium")).not.toBeNull();
  });

  it("confidence=0.45 → 'medium' class", () => {
    const chain = makeChain({ confidence: 0.45 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-conf-medium")).not.toBeNull();
  });

  it("confidence=0.44 → 'low' class", () => {
    const chain = makeChain({ confidence: 0.44 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-conf-low")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Chain with empty links array
// ═════════════════════════════════════════════════════════════════════════════════

describe("chain with empty links", () => {
  it("empty links → renders confidence section but no flow/mitigations/impacts", () => {
    const chain = makeChain({ links: [], confidence: 0.5 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Confidence section still renders
    expect(container.textContent).toContain("50%");
    // No flow chain (WhereSection returns null when no sources/sinks)
    expect(container.querySelector(".ec5-flow-chain")).toBeNull();
    // No mitigations
    expect(container.querySelector(".ec5-mitigations")).toBeNull();
    // No impact blocks
    expect(container.querySelector(".ec5-impact-block")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Link rendering by type
// ═════════════════════════════════════════════════════════════════════════════════

describe("link rendering by type", () => {
  it("source link → renders 'ENTRY' badge in flow, source_type in prose, location, observed, rationale", () => {
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "user-parameter",
        location: "src/index.ts:10",
        observed: "user input flows",
        rationale: "Direct user input",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // ENTRY badge in WhereSection flow
    expect(container.textContent).toContain("ENTRY");
    // Source type label rendered lowercase in WhatSection prose
    expect(container.textContent).toContain("user-controlled parameter");
    expect(container.textContent).toContain("src/index.ts:10");
    expect(container.textContent).toContain("user input flows");
    expect(container.textContent).toContain("Direct user input");
  });

  it("propagation link → renders 'FLOW' badge in flow timeline", () => {
    // Propagation alone won't show in WhereSection (needs source or sink).
    // Include a source so WhereSection renders the flow chain.
    const chain = makeChain({
      links: [
        {
          type: "source",
          source_type: "user-parameter",
          location: "src/a.ts:1",
          observed: "input",
          rationale: "test",
        },
        {
          type: "propagation",
          propagation_type: "variable-assignment",
          location: "src/a.ts:5",
          observed: "const x = input",
        },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("FLOW");
    // propagation_type is not rendered as a label in the new component
    // but the location and observed text are shown in the flow node
    expect(container.textContent).toContain("src/a.ts:5");
    expect(container.textContent).toContain("const x = input");
  });

  it("sink link → renders 'DANGER' badge, sink_type in prose, optional CVE tag", () => {
    const chain = makeChain({
      links: [{
        type: "sink",
        sink_type: "command-execution",
        location: "src/b.ts:20",
        observed: "exec(input)",
        cve_precedent: "CVE-2025-12345",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("DANGER");
    // Sink type rendered lowercase in WhatSection prose
    expect(container.textContent).toContain("operating system command execution");
    expect(container.textContent).toContain("CVE-2025-12345");
  });

  it("sink link without cve_precedent → no CVE tag, no crash", () => {
    const chain = makeChain({
      links: [{
        type: "sink",
        sink_type: "sql-execution",
        location: "src/c.ts:5",
        observed: "query(input)",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("DANGER");
    expect(container.querySelector(".ec5-flow-cve")).toBeNull();
  });

  it("mitigation link (present=true) → renders ✓ icon under 'Controls detected'", () => {
    const chain = makeChain({
      links: [{
        type: "mitigation",
        mitigation_type: "input-validation",
        present: true,
        location: "src/d.ts:10",
        detail: "Input is validated",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Controls detected");
    // mitigation_type rendered with dashes→spaces
    expect(container.textContent).toContain("input validation");
    expect(container.textContent).toContain("Input is validated");
    expect(container.querySelector(".ec5-mit-present")).not.toBeNull();
  });

  it("mitigation link (present=false) → renders ✗ icon under 'Missing security controls'", () => {
    const chain = makeChain({
      links: [{
        type: "mitigation",
        mitigation_type: "input-validation",
        present: false,
        location: "src/d.ts:10",
        detail: "No validation found",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Missing security controls");
    expect(container.textContent).toContain("input validation");
    expect(container.textContent).toContain("No validation found");
    expect(container.querySelector(".ec5-mit-absent")).not.toBeNull();
  });

  it("impact link → renders impact_type, scope, exploitability, scenario in prose", () => {
    const chain = makeChain({
      links: [{
        type: "impact",
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "trivial",
        scenario: "Attacker gains shell access",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Impact type from label map
    expect(container.textContent).toContain("Remote Code Execution (RCE)");
    // Scope from label map
    expect(container.textContent).toContain("Server Host System");
    // Exploitability from label map
    expect(container.textContent).toContain("Trivial");
    expect(container.textContent).toContain("Attacker gains shell access");
  });

  it("unknown link type → renders nothing (no crash)", () => {
    const chain = makeChain({
      links: [{ type: "unknown" } as unknown as EvidenceChainData["links"][number]],
    });
    expect(() =>
      render(<EvidenceChainViz chain={chain} />)
    ).not.toThrow();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Truncation
// ═════════════════════════════════════════════════════════════════════════════════

describe("truncation", () => {
  it("observed on source link: 'x'.repeat(200) → truncated in prose at 100 chars + '…'", () => {
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "user-parameter",
        location: "a.ts:1",
        observed: "x".repeat(200),
        rationale: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const text = container.textContent ?? "";
    expect(text).not.toContain("x".repeat(200)); // truncated
    expect(text).toContain("\u2026"); // has ellipsis
    // WhatSection truncates at 100, WhereSection flow truncates at 80
    expect(text).toContain("x".repeat(80)); // at least 80 chars present (flow)
    expect(text).not.toContain("x".repeat(101)); // WhatSection limit is 100
  });

  it("observed on source link: 'x'.repeat(50) → not truncated", () => {
    const short = "x".repeat(50);
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "user-parameter",
        location: "a.ts:1",
        observed: short,
        rationale: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain(short);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence factor display
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence factor display", () => {
  it("factor with positive adjustment → '+0.15'", () => {
    const chain = makeChain({
      confidence_factors: [
        { factor: "ast_taint", adjustment: 0.15, rationale: "AST confirmed" },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("+0.15");
  });

  it("factor with negative adjustment → '-0.10'", () => {
    const chain = makeChain({
      confidence_factors: [
        { factor: "hop_count", adjustment: -0.10, rationale: "Long chain" },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("-0.10");
  });

  it("factor with adjustment=0 → '+0.00'", () => {
    const chain = makeChain({
      confidence_factors: [
        { factor: "neutral", adjustment: 0, rationale: "Neutral" },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("+0.00");
  });

  it("5 factors → all rendered (underscores replaced with spaces)", () => {
    const factors = Array.from({ length: 5 }, (_, i) => ({
      factor: `factor_${i}`,
      adjustment: i * 0.05,
      rationale: `Rationale ${i}`,
    }));
    const chain = makeChain({ confidence_factors: factors });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Component renders factor names with underscores replaced by spaces
    for (let i = 0; i < factors.length; i++) {
      expect(container.textContent).toContain(`factor ${i}`);
    }
  });

  it("0 factors → factors section not rendered", () => {
    const chain = makeChain({ confidence_factors: [] });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-factors")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Threat reference
// ═════════════════════════════════════════════════════════════════════════════════

describe("threat reference", () => {
  it("with full threat_reference (id, title, year, url) → all rendered", () => {
    const chain = makeChain({
      threat_reference: {
        id: "CVE-2025-12345",
        title: "Command Injection in MCP",
        year: 2025,
        url: "https://example.com",
        relevance: "Direct match",
      },
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("CVE-2025-12345");
    expect(container.textContent).toContain("Command Injection in MCP");
    expect(container.textContent).toContain("(2025)");
  });

  it("with threat_reference missing year → no year span", () => {
    const chain = makeChain({
      threat_reference: {
        id: "CWE-78",
        title: "OS Command Injection",
        relevance: "Pattern match",
      },
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("CWE-78");
    expect(container.querySelector(".ec5-ref-year")).toBeNull();
  });

  it("without threat_reference → reference section not rendered", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-reference")).toBeNull();
  });

  it("with threat_reference but year=0 → year is falsy, no year span", () => {
    const chain = makeChain({
      threat_reference: {
        id: "TEST-001",
        title: "Test",
        year: 0,
        relevance: "Test",
      },
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // year=0 is falsy, so {reference.year && ...} won't render
    expect(container.querySelector(".ec5-ref-year")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Label fallbacks
// ═════════════════════════════════════════════════════════════════════════════════

describe("label fallbacks", () => {
  it("unknown source_type 'custom-source' → renders raw 'custom-source' in prose", () => {
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "custom-source",
        location: "a.ts:1",
        observed: "test",
        rationale: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Unknown source_type falls through label map → rendered raw, lowercased in prose
    expect(container.textContent).toContain("custom-source");
  });

  it("unknown sink_type 'custom-sink' → renders raw 'custom-sink' in prose", () => {
    const chain = makeChain({
      links: [{
        type: "sink",
        sink_type: "custom-sink",
        location: "a.ts:1",
        observed: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("custom-sink");
  });

  it("known source_type 'user-parameter' → renders 'user-controlled parameter' in prose", () => {
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "user-parameter",
        location: "a.ts:1",
        observed: "test",
        rationale: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Label map: "user-parameter" → "User-Controlled Parameter", then .toLowerCase() in prose
    expect(container.textContent).toContain("user-controlled parameter");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Flow timeline structure
// ═════════════════════════════════════════════════════════════════════════════════

describe("flow timeline structure", () => {
  it("3 flow links (source+propagation+sink) → rendered with arrows between them", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".ec5-flow-arrow");
    // source→propagation arrow, propagation→sink arrow = 2 arrows
    expect(arrows).toHaveLength(2);
  });

  it("1 source link → 0 arrows", () => {
    const chain = makeChain({
      links: [{
        type: "source",
        source_type: "user-parameter",
        location: "a.ts:1",
        observed: "test",
        rationale: "test",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".ec5-flow-arrow");
    expect(arrows).toHaveLength(0);
  });

  it("mixed: source + sink + mitigation + impact → 1 arrow (between source and sink in flow)", () => {
    const chain = makeChain({
      links: [
        { type: "source", source_type: "user-parameter", location: "a.ts:1", observed: "test", rationale: "test" },
        { type: "sink", sink_type: "command-execution", location: "b.ts:2", observed: "exec()" },
        { type: "mitigation", mitigation_type: "validation", present: true, location: "c.ts:3", detail: "present" },
        { type: "impact", impact_type: "remote-code-execution", scope: "server-host", exploitability: "trivial", scenario: "shell" },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".ec5-flow-arrow");
    // Only flow nodes (source, propagation, sink) get arrows; 1 arrow between source→sink
    expect(arrows).toHaveLength(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Section rendering
// ═════════════════════════════════════════════════════════════════════════════════

describe("section rendering", () => {
  it("chain with only mitigation links → mitigations section, no flow chain", () => {
    const chain = makeChain({
      links: [{
        type: "mitigation",
        mitigation_type: "sanitizer",
        present: true,
        location: "a.ts:1",
        detail: "Sanitizer present",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-mitigations")).not.toBeNull();
    // WhereSection returns null when no sources/sinks
    expect(container.querySelector(".ec5-flow-chain")).toBeNull();
  });

  it("chain with only impact links → impact block rendered, no flow chain", () => {
    const chain = makeChain({
      links: [{
        type: "impact",
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "moderate",
        scenario: "Data leak",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-impact-block")).not.toBeNull();
    expect(container.querySelector(".ec5-flow-chain")).toBeNull();
  });

  it("chain with all link types → all sections render", () => {
    const chain = makeChain({
      links: [
        { type: "source", source_type: "user-parameter", location: "a.ts:1", observed: "input", rationale: "user" },
        { type: "propagation", propagation_type: "direct-pass", location: "b.ts:2", observed: "pass" },
        { type: "sink", sink_type: "command-execution", location: "c.ts:3", observed: "exec()" },
        { type: "mitigation", mitigation_type: "validation", present: false, location: "d.ts:4", detail: "missing" },
        { type: "impact", impact_type: "remote-code-execution", scope: "server-host", exploitability: "trivial", scenario: "shell" },
      ],
      threat_reference: { id: "CVE-2025-1", title: "Test", year: 2025, relevance: "direct" },
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec5-flow-chain")).not.toBeNull();
    expect(container.querySelector(".ec5-mitigations")).not.toBeNull();
    expect(container.querySelector(".ec5-impact-block")).not.toBeNull();
    expect(container.querySelector(".ec5-reference")).not.toBeNull();
    expect(container.querySelector(".ec5-confidence")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════════

describe("edge cases", () => {
  it("50 links → no crash", () => {
    const links = Array.from({ length: 50 }, (_, i) => ({
      type: "source" as const,
      source_type: "user-parameter",
      location: `file.ts:${i}`,
      observed: `Step ${i}`,
      rationale: "test",
    }));
    const chain = makeChain({ links });
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("confidence-only mode renders percentage", () => {
    const { container } = render(
      <EvidenceChainViz chain={undefined} confidence={0.73} />
    );
    expect(container.textContent).toContain("73%");
  });

  it("full chain renders confidence from chain, not from prop", () => {
    const chain = makeChain({ confidence: 0.88 });
    const { container } = render(
      <EvidenceChainViz chain={chain} confidence={0.50} />
    );
    expect(container.textContent).toContain("88%");
  });
});
