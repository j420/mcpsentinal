// @vitest-environment jsdom
/**
 * EvidenceChainViz Critical Test Suite
 *
 * Tests the main-branch EvidenceChainViz component which:
 * - Takes { chain: EvidenceChainData | null | undefined, confidence?: number }
 * - Uses discriminated union link types (SourceLink, PropagationLink, etc.)
 * - Server component (no "use client"), CSS class-based rendering
 * - confLevel thresholds: >=0.70 high, >=0.45 medium, <0.45 low
 * - Confidence display: Math.round(confidence * 100) — NO clamping
 * - truncate(s, max): s.slice(0, max) + "…" — no null guard (types require string)
 * - Badges: SOURCE, FLOW, SINK, ✓ MITIGATED / ✗ UNMITIGATED, IMPACT
 * - Confidence factors: adjustment (number) with +/- prefix, .toFixed(2)
 * - Threat reference: id, title, optional year/url
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
    // Should NOT render full chain sections
    expect(container.querySelector(".ec-chain")).toBeNull();
    expect(container.querySelector(".ec-confidence-only")).not.toBeNull();
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
    expect(container.querySelector(".ec-conf-high")).not.toBeNull();
  });

  it("confidence=0.69 → 'medium' class", () => {
    const chain = makeChain({ confidence: 0.69 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-conf-medium")).not.toBeNull();
  });

  it("confidence=0.45 → 'medium' class", () => {
    const chain = makeChain({ confidence: 0.45 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-conf-medium")).not.toBeNull();
  });

  it("confidence=0.44 → 'low' class", () => {
    const chain = makeChain({ confidence: 0.44 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-conf-low")).not.toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Chain with empty links array
// ═════════════════════════════════════════════════════════════════════════════════

describe("chain with empty links", () => {
  it("empty links → renders confidence bar but no flow/mitigations/impacts", () => {
    const chain = makeChain({ links: [], confidence: 0.5 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Confidence bar still renders
    expect(container.textContent).toContain("50%");
    // No flow timeline
    expect(container.querySelector(".ec-flow")).toBeNull();
    // No mitigations
    expect(container.querySelector(".ec-mitigations")).toBeNull();
    // No impacts
    expect(container.querySelector(".ec-impacts")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Link rendering by type
// ═════════════════════════════════════════════════════════════════════════════════

describe("link rendering by type", () => {
  it("source link → renders 'SOURCE' badge, source_type label, location, observed, rationale", () => {
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
    expect(container.textContent).toContain("SOURCE");
    expect(container.textContent).toContain("User Parameter");
    expect(container.textContent).toContain("src/index.ts:10");
    expect(container.textContent).toContain("user input flows");
    expect(container.textContent).toContain("Direct user input");
  });

  it("propagation link → renders 'FLOW' badge, propagation_type label", () => {
    const chain = makeChain({
      links: [{
        type: "propagation",
        propagation_type: "variable-assignment",
        location: "src/a.ts:5",
        observed: "const x = input",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("FLOW");
    expect(container.textContent).toContain("Variable Assignment");
  });

  it("sink link → renders 'SINK' badge, sink_type label, optional CVE tag", () => {
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
    expect(container.textContent).toContain("SINK");
    expect(container.textContent).toContain("Command Execution");
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
    expect(container.textContent).toContain("SINK");
    expect(container.querySelector(".ec-cve")).toBeNull();
  });

  it("mitigation link (present=true) → renders '✓ MITIGATED'", () => {
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
    expect(container.textContent).toContain("✓ MITIGATED");
    expect(container.querySelector(".ec-mit-present")).not.toBeNull();
  });

  it("mitigation link (present=false) → renders '✗ UNMITIGATED'", () => {
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
    expect(container.textContent).toContain("✗ UNMITIGATED");
    expect(container.querySelector(".ec-mit-absent")).not.toBeNull();
  });

  it("impact link → renders 'IMPACT' badge, impact_type, scope, exploitability, scenario", () => {
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
    expect(container.textContent).toContain("IMPACT");
    expect(container.textContent).toContain("Remote Code Execution");
    expect(container.textContent).toContain("server host"); // scope with - replaced by space
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
  it("observed on source link: 'x'.repeat(200) → truncated at 120 chars + '…'", () => {
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
    expect(text).toContain("…"); // has ellipsis
    expect(text).toContain("x".repeat(120)); // first 120 chars present
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

  it("5 factors → all rendered", () => {
    const factors = Array.from({ length: 5 }, (_, i) => ({
      factor: `factor_${i}`,
      adjustment: i * 0.05,
      rationale: `Rationale ${i}`,
    }));
    const chain = makeChain({ confidence_factors: factors });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    for (const f of factors) {
      expect(container.textContent).toContain(f.factor);
    }
  });

  it("0 factors → details section not rendered", () => {
    const chain = makeChain({ confidence_factors: [] });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-factors")).toBeNull();
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
    expect(container.querySelector(".ec-ref-year")).toBeNull();
  });

  it("without threat_reference → section not rendered", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-reference")).toBeNull();
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
    // year=0 is falsy, so {chain.threat_reference.year && ...} won't render
    expect(container.querySelector(".ec-ref-year")).toBeNull();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Label fallbacks
// ═════════════════════════════════════════════════════════════════════════════════

describe("label fallbacks", () => {
  it("unknown source_type 'custom-source' → renders raw 'custom-source'", () => {
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
    expect(container.textContent).toContain("custom-source");
  });

  it("unknown sink_type 'custom-sink' → renders raw 'custom-sink'", () => {
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

  it("known source_type 'user-parameter' → renders 'User Parameter'", () => {
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
    expect(container.textContent).toContain("User Parameter");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Flow timeline structure
// ═════════════════════════════════════════════════════════════════════════════════

describe("flow timeline structure", () => {
  it("3 flow links → rendered with connectors between them", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const connectors = container.querySelectorAll(".ec-connector");
    // 3 flow links → 2 connectors (n-1)
    expect(connectors).toHaveLength(2);
  });

  it("1 flow link → 0 connectors", () => {
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
    const connectors = container.querySelectorAll(".ec-connector");
    expect(connectors).toHaveLength(0);
  });

  it("mixed: 2 flow + 1 mitigation + 1 impact → only 1 connector (flow links only)", () => {
    const chain = makeChain({
      links: [
        { type: "source", source_type: "user-parameter", location: "a.ts:1", observed: "test", rationale: "test" },
        { type: "sink", sink_type: "command-execution", location: "b.ts:2", observed: "exec()" },
        { type: "mitigation", mitigation_type: "validation", present: true, location: "c.ts:3", detail: "present" },
        { type: "impact", impact_type: "remote-code-execution", scope: "host", exploitability: "trivial", scenario: "shell" },
      ],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const connectors = container.querySelectorAll(".ec-connector");
    expect(connectors).toHaveLength(1); // only between 2 flow links
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Section rendering
// ═════════════════════════════════════════════════════════════════════════════════

describe("section rendering", () => {
  it("chain with only mitigation links → mitigations section, no flow", () => {
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
    expect(container.querySelector(".ec-mitigations")).not.toBeNull();
    expect(container.querySelector(".ec-flow")).toBeNull();
  });

  it("chain with only impact links → impacts section, no flow", () => {
    const chain = makeChain({
      links: [{
        type: "impact",
        impact_type: "data-exfiltration",
        scope: "org",
        exploitability: "moderate",
        scenario: "Data leak",
      }],
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-impacts")).not.toBeNull();
    expect(container.querySelector(".ec-flow")).toBeNull();
  });

  it("chain with all link types → all sections render", () => {
    const chain = makeChain({
      links: [
        { type: "source", source_type: "user-parameter", location: "a.ts:1", observed: "input", rationale: "user" },
        { type: "propagation", propagation_type: "direct-pass", location: "b.ts:2", observed: "pass" },
        { type: "sink", sink_type: "command-execution", location: "c.ts:3", observed: "exec()" },
        { type: "mitigation", mitigation_type: "validation", present: false, location: "d.ts:4", detail: "missing" },
        { type: "impact", impact_type: "remote-code-execution", scope: "host", exploitability: "trivial", scenario: "shell" },
      ],
      threat_reference: { id: "CVE-2025-1", title: "Test", year: 2025, relevance: "direct" },
    });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.querySelector(".ec-flow")).not.toBeNull();
    expect(container.querySelector(".ec-mitigations")).not.toBeNull();
    expect(container.querySelector(".ec-impacts")).not.toBeNull();
    expect(container.querySelector(".ec-reference")).not.toBeNull();
    expect(container.querySelector(".ec-confidence")).not.toBeNull();
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
