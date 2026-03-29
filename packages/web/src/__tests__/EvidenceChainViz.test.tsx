// @vitest-environment jsdom
/**
 * EvidenceChainViz Test Suite — packages/web/src/components/EvidenceChainViz.tsx
 *
 * Tests rendering correctness, null-safety (4 bug fixes verified), and
 * edge cases for the evidence chain visualization component.
 *
 * Uses Vitest + React Testing Library (jsdom environment).
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render, screen } from "@testing-library/react";
import { EvidenceChainViz, type EvidenceChain, type EvidenceLink } from "../components/EvidenceChainViz";

// ── Fixtures ──────────────────────────────────────────────────────────────────

function makeLink(overrides: Partial<EvidenceLink> = {}): EvidenceLink {
  return {
    type: "source",
    location: "src/handler.ts:42",
    observed: "req.body.input passed to exec()",
    rationale: "User-controlled input flows to command execution",
    source_type: "user-parameter",
    ...overrides,
  };
}

function makeChain(overrides: Partial<EvidenceChain> = {}): EvidenceChain {
  return {
    links: [
      makeLink({ type: "source", source_type: "user-parameter" }),
      makeLink({ type: "propagation", propagation_type: "variable-assignment", location: "src/handler.ts:45", observed: "const cmd = input" }),
      makeLink({ type: "sink", sink_type: "command-execution", location: "src/handler.ts:48", observed: "exec(cmd)" }),
    ],
    confidence: 0.92,
    confidence_factors: [
      { factor: "ast_taint", value: 0.95, description: "AST-confirmed taint flow" },
      { factor: "hop_count", value: 0.85, description: "2-hop propagation" },
    ],
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG FIX 1: chain.links null/undefined safety
// ═══════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 1: chain.links null/undefined safety", () => {
  it("renders 'No evidence chain available' when links is null", () => {
    const { container } = render(<EvidenceChainViz chain={{ links: null }} />);
    expect(container.textContent).toContain("No evidence chain available");
  });

  it("renders 'No evidence chain available' when links is undefined", () => {
    const { container } = render(<EvidenceChainViz chain={{}} />);
    expect(container.textContent).toContain("No evidence chain available");
  });

  it("does NOT crash when links is null (previously threw TypeError)", () => {
    // Before fix: chain.links.filter(...) would throw
    // "Cannot read properties of null (reading 'filter')"
    expect(() =>
      render(<EvidenceChainViz chain={{ links: null }} />)
    ).not.toThrow();
  });

  it("renders 'No evidence chain available' for empty links array", () => {
    const { container } = render(<EvidenceChainViz chain={{ links: [] }} />);
    expect(container.textContent).toContain("No evidence chain available");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BUG FIX 2: truncate() null/undefined safety
// ═══════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 2: truncate() null/undefined safety", () => {
  it("renders link with null location without crashing", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ location: null })],
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("renders link with undefined observed without crashing", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ observed: undefined })],
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("renders link with null rationale without crashing", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ rationale: null })],
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("truncates long strings correctly", () => {
    const longStr = "A".repeat(300);
    const chain: EvidenceChain = {
      links: [makeLink({ observed: longStr })],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // Observed is truncated at 200 chars
    const text = container.textContent ?? "";
    expect(text.includes("A".repeat(200))).toBe(false); // truncated below 300
    expect(text).toContain("…"); // has ellipsis
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BUG FIX 3: confidence_factors null/undefined safety
// ═══════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 3: confidence_factors null/undefined safety", () => {
  it("renders without crashing when confidence_factors is null", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 0.8,
      confidence_factors: null,
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("renders without crashing when confidence_factors is undefined", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 0.8,
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });

  it("does not render factors section when confidence_factors is null", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence_factors: null,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).not.toContain("Confidence Factors");
  });

  it("does not render factors section when confidence_factors is empty", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence_factors: [],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).not.toContain("Confidence Factors");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// BUG FIX 4: Confidence bar clamped to 0-100%
// ═══════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 4: Confidence clamped to 0-100%", () => {
  it("clamps confidence 1.5 to 100%", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 1.5,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("100%");
    expect(container.textContent).not.toContain("150%");
  });

  it("clamps confidence -0.5 to 0%", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: -0.5,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("0%");
    expect(container.textContent).not.toContain("-50%");
  });

  it("renders 92% for confidence 0.92", () => {
    const chain = makeChain({ confidence: 0.92 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("92%");
  });

  it("renders 0% for confidence 0.0", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 0.0,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("0%");
  });

  it("renders 100% for confidence 1.0", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 1.0,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("100%");
  });

  it("does not render confidence bar when confidence is null", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: null,
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    // No confidence bar rendered
    const bars = container.querySelectorAll(".evidence-confidence-bar");
    expect(bars).toHaveLength(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Flow section
// ═══════════════════════════════════════════════════════════════════════════════

describe("rendering: flow section", () => {
  it("renders source → propagation → sink links with Data Flow header", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Data Flow");
    expect(container.textContent).toContain("Source");
    expect(container.textContent).toContain("Propagation");
    expect(container.textContent).toContain("Sink");
  });

  it("renders flow arrows between links", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".evidence-flow-arrow");
    // 3 flow links → 2 arrows
    expect(arrows).toHaveLength(2);
  });

  it("renders link locations and observations", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("src/handler.ts:42");
    expect(container.textContent).toContain("exec(cmd)");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Mitigation links
// ═══════════════════════════════════════════════════════════════════════════════

describe("rendering: mitigation links", () => {
  it("renders mitigation with present=true as '✓ Present'", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "mitigation", mitigation_type: "input-validation", present: true }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("✓ Present");
  });

  it("renders mitigation with present=false as '✗ Missing'", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "mitigation", mitigation_type: "input-validation", present: false }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("✗ Missing");
  });

  it("shows 'Mitigations' section header", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "mitigation", mitigation_type: "sanitizer" }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Mitigations");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Impact links
// ═══════════════════════════════════════════════════════════════════════════════

describe("rendering: impact links", () => {
  it("renders impact section with scope in full mode", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "impact", impact_type: "remote-code-execution", scope: "server-host" }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} compact={false} />);
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).toContain("server-host");
  });

  it("hides impact section in compact mode", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "impact", impact_type: "remote-code-execution", scope: "server-host" }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} compact />);
    expect(container.textContent).not.toContain("Impact");
    expect(container.textContent).not.toContain("server-host");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Compact mode
// ═══════════════════════════════════════════════════════════════════════════════

describe("compact mode", () => {
  it("hides rationale in compact mode", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ rationale: "This is the detailed rationale" })],
    };
    const { container: compactContainer } = render(<EvidenceChainViz chain={chain} compact />);
    expect(compactContainer.textContent).not.toContain("This is the detailed rationale");

    const { container: fullContainer } = render(<EvidenceChainViz chain={chain} compact={false} />);
    expect(fullContainer.textContent).toContain("This is the detailed rationale");
  });

  it("hides confidence factors in compact mode", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} compact />);
    expect(container.textContent).not.toContain("Confidence Factors");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Confidence factors
// ═══════════════════════════════════════════════════════════════════════════════

describe("confidence factors", () => {
  it("renders factor descriptions and percentages in full mode", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} compact={false} />);
    expect(container.textContent).toContain("Confidence Factors");
    expect(container.textContent).toContain("AST-confirmed taint flow");
    expect(container.textContent).toContain("95%");
    expect(container.textContent).toContain("2-hop propagation");
    expect(container.textContent).toContain("85%");
  });

  it("uses factor name when description is empty", () => {
    const chain: EvidenceChain = {
      links: [makeLink()],
      confidence: 0.5,
      confidence_factors: [
        { factor: "custom_factor", value: 0.7, description: "" },
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("custom_factor");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rendering: Link subtypes
// ═══════════════════════════════════════════════════════════════════════════════

describe("link subtypes", () => {
  it("formats subtype from snake_case to Title Case", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ type: "source", source_type: "user-parameter" })],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("User Parameter");
  });

  it("renders without subtype when all type fields are null", () => {
    const chain: EvidenceChain = {
      links: [{
        type: "source",
        source_type: null,
        propagation_type: null,
        sink_type: null,
        mitigation_type: null,
        impact_type: null,
      }],
    };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
    // Should still render the "Source" badge without subtype
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════════

describe("edge cases", () => {
  it("handles chain with only mitigation links (no flow)", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "mitigation", mitigation_type: "sanitizer", present: true }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Mitigations");
    expect(container.textContent).not.toContain("Data Flow");
  });

  it("handles chain with only impact links", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "impact", impact_type: "rce", scope: "host" }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).not.toContain("Data Flow");
  });

  it("handles chain with all link types", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "source" }),
        makeLink({ type: "propagation" }),
        makeLink({ type: "sink" }),
        makeLink({ type: "mitigation", present: false }),
        makeLink({ type: "impact", scope: "network" }),
      ],
      confidence: 0.8,
      confidence_factors: [{ factor: "f1", value: 0.8, description: "Test" }],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("Data Flow");
    expect(container.textContent).toContain("Mitigations");
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).toContain("80%");
  });

  it("renders many links without performance issues", () => {
    const links = Array.from({ length: 50 }, (_, i) =>
      makeLink({
        type: i % 3 === 0 ? "source" : i % 3 === 1 ? "propagation" : "sink",
        location: `file.ts:${i}`,
        observed: `Step ${i}`,
      })
    );
    const chain: EvidenceChain = { links };
    expect(() => render(<EvidenceChainViz chain={chain} />)).not.toThrow();
  });
});
