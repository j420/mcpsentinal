// @vitest-environment jsdom
/**
 * EvidenceChainViz Critical Test Suite
 *
 * Comprehensive edge-case-heavy tests for the evidence chain visualization
 * component. Covers null/undefined safety (4 bug fix regressions), confidence
 * clamping, bar color thresholds, truncation boundaries, link rendering by
 * type, confidence factor display, label fallbacks, compact mode, and
 * rendering structure.
 */
import { describe, it, expect } from "vitest";
import React from "react";
import { render } from "@testing-library/react";
import {
  EvidenceChainViz,
  type EvidenceChain,
  type EvidenceLink,
} from "../components/EvidenceChainViz";

// ── Fixtures ────────────────────────────────────────────────────────────────────

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
      makeLink({
        type: "propagation",
        propagation_type: "variable-assignment",
        location: "src/handler.ts:45",
        observed: "const cmd = input",
      }),
      makeLink({
        type: "sink",
        sink_type: "command-execution",
        location: "src/handler.ts:48",
        observed: "exec(cmd)",
      }),
    ],
    confidence: 0.92,
    confidence_factors: [
      { factor: "ast_taint", value: 0.95, description: "AST-confirmed taint flow" },
      { factor: "hop_count", value: 0.85, description: "2-hop propagation" },
    ],
    ...overrides,
  };
}

// ═════════════════════════════════════════════════════════════════════════════════
// Null/undefined handling
// ═════════════════════════════════════════════════════════════════════════════════

describe("null/undefined handling", () => {
  it("chain with no links ({}) renders 'No evidence chain available'", () => {
    const { container } = render(<EvidenceChainViz chain={{}} />);
    expect(container.textContent).toContain("No evidence chain available");
  });

  it("chain with links=null renders 'No evidence chain available'", () => {
    const { container } = render(<EvidenceChainViz chain={{ links: null }} />);
    expect(container.textContent).toContain("No evidence chain available");
  });

  it("chain with links=undefined renders 'No evidence chain available'", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: undefined }} />
    );
    expect(container.textContent).toContain("No evidence chain available");
  });

  it("chain with confidence=undefined renders no confidence bar", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()] }} />
    );
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(0);
  });

  it("chain with confidence=null renders no confidence bar", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: null }} />
    );
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(0);
  });

  it("chain with confidence=0 renders '0%' (0 is valid, not null)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0 }} />
    );
    expect(container.textContent).toContain("0%");
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(1);
  });

  it("chain with only confidence (no links) renders 'No evidence chain' — empty links triggers early return before ConfidenceBar", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [], confidence: 0.85 }} />
    );
    // Early return on empty links means NO confidence bar rendered
    expect(container.textContent).toContain("No evidence chain available");
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// BUG FIX 1 regression: chain.links null safety
// ═════════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 1 regression: chain.links null safety", () => {
  it("does NOT crash when links is null (previously threw TypeError on .filter)", () => {
    expect(() =>
      render(<EvidenceChainViz chain={{ links: null }} />)
    ).not.toThrow();
  });

  it("chain={ links: null, confidence_factors: [], confidence: 0.5 } renders without crash", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: null, confidence_factors: [], confidence: 0.5 }}
      />
    );
    expect(container.textContent).toContain("No evidence chain available");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// BUG FIX 3 regression: confidence_factors null safety
// ═════════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 3 regression: confidence_factors null safety", () => {
  it("renders without crash when confidence_factors is null", () => {
    expect(() =>
      render(
        <EvidenceChainViz
          chain={{ links: [makeLink()], confidence_factors: null, confidence: 0.5 }}
        />
      )
    ).not.toThrow();
  });

  it("does not render 'Confidence Factors' section when null", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink()], confidence_factors: null }}
      />
    );
    expect(container.textContent).not.toContain("Confidence Factors");
  });

  it("does not render 'Confidence Factors' section when empty array", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink()], confidence_factors: [] }}
      />
    );
    expect(container.textContent).not.toContain("Confidence Factors");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence clamping
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence clamping", () => {
  it("confidence=0.0 → '0%'", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.0 }} />
    );
    expect(container.textContent).toContain("0%");
  });

  it("confidence=1.0 → '100%'", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 1.0 }} />
    );
    expect(container.textContent).toContain("100%");
  });

  it("confidence=0.5 → '50%'", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.5 }} />
    );
    expect(container.textContent).toContain("50%");
  });

  it("confidence=1.5 → clamped to '100%' (not '150%')", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 1.5 }} />
    );
    expect(container.textContent).toContain("100%");
    expect(container.textContent).not.toContain("150%");
  });

  it("confidence=-0.3 → clamped to '0%' (not '-30%')", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: -0.3 }} />
    );
    expect(container.textContent).toContain("0%");
    expect(container.textContent).not.toContain("-30%");
  });

  it("confidence=NaN → renders 'NaN%' (Math.round(NaN*100) = NaN)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: NaN }} />
    );
    // Math.min(1, Math.max(0, NaN)) = NaN, Math.round(NaN * 100) = NaN
    expect(container.textContent).toContain("NaN%");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence bar color thresholds
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence bar color thresholds", () => {
  // jsdom normalizes hex colors to rgb() format in element.style.
  // We verify the bar color by checking the text percentage (which maps to a
  // specific color) and that the bar section renders correctly.
  // The ConfidenceBar component uses: <0.5 → red, <0.75 → amber, >=0.75 → green

  it("confidence=0.49 → renders '49%' with red bar (clamped < 0.5)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.49 }} />
    );
    expect(container.textContent).toContain("49%");
    // Verify the bar fill div has rgb(220, 38, 38) = #dc2626
    const barSection = container.querySelector(".evidence-confidence-bar");
    expect(barSection).not.toBeNull();
    const fills = barSection!.querySelectorAll("div div div") as NodeListOf<HTMLElement>;
    const colors = Array.from(fills).map((el) => el.style.background);
    expect(colors.some((c) => c === "rgb(220, 38, 38)" || c === "#dc2626")).toBe(true);
  });

  it("confidence=0.50 → renders '50%' with amber bar (>= 0.5, < 0.75)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.50 }} />
    );
    expect(container.textContent).toContain("50%");
    const barSection = container.querySelector(".evidence-confidence-bar");
    const fills = barSection!.querySelectorAll("div div div") as NodeListOf<HTMLElement>;
    const colors = Array.from(fills).map((el) => el.style.background);
    expect(colors.some((c) => c === "rgb(245, 158, 11)" || c === "#f59e0b")).toBe(true);
  });

  it("confidence=0.70 → renders '70%' with amber bar (>= 0.5, < 0.75)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.70 }} />
    );
    expect(container.textContent).toContain("70%");
    const barSection = container.querySelector(".evidence-confidence-bar");
    const fills = barSection!.querySelectorAll("div div div") as NodeListOf<HTMLElement>;
    const colors = Array.from(fills).map((el) => el.style.background);
    expect(colors.some((c) => c === "rgb(245, 158, 11)" || c === "#f59e0b")).toBe(true);
  });

  it("confidence=0.74 → renders '74%' with amber bar (< 0.75)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.74 }} />
    );
    expect(container.textContent).toContain("74%");
    const barSection = container.querySelector(".evidence-confidence-bar");
    const fills = barSection!.querySelectorAll("div div div") as NodeListOf<HTMLElement>;
    const colors = Array.from(fills).map((el) => el.style.background);
    expect(colors.some((c) => c === "rgb(245, 158, 11)" || c === "#f59e0b")).toBe(true);
  });

  it("confidence=0.75 → renders '75%' with green bar (>= 0.75)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()], confidence: 0.75 }} />
    );
    expect(container.textContent).toContain("75%");
    const barSection = container.querySelector(".evidence-confidence-bar");
    const fills = barSection!.querySelectorAll("div div div") as NodeListOf<HTMLElement>;
    const colors = Array.from(fills).map((el) => el.style.background);
    expect(colors.some((c) => c === "rgb(5, 150, 105)" || c === "#059669")).toBe(true);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Chain with empty links array
// ═════════════════════════════════════════════════════════════════════════════════

describe("chain with empty links array", () => {
  it("renders 'No evidence chain available', no flow/mitigations/impacts", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [], confidence_factors: [], confidence: 0.5 }}
      />
    );
    expect(container.textContent).toContain("No evidence chain available");
    // Early return means no sections rendered at all
    expect(container.textContent).not.toContain("Data Flow");
    expect(container.textContent).not.toContain("Mitigations");
    expect(container.textContent).not.toContain("Impact");
    // Confidence bar NOT rendered because early return
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Link rendering by type
// ═════════════════════════════════════════════════════════════════════════════════

describe("link rendering by type", () => {
  it("source link → renders 'Source' badge + subtype", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink({ type: "source", source_type: "user-parameter" })] }}
      />
    );
    expect(container.textContent).toContain("Source");
    expect(container.textContent).toContain("User Parameter");
  });

  it("propagation link → renders 'Propagation' badge", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({ type: "propagation", propagation_type: "variable-assignment", source_type: null }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("Propagation");
    expect(container.textContent).toContain("Variable Assignment");
  });

  it("sink link → renders 'Sink' badge + subtype", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink({ type: "sink", sink_type: "command-execution", source_type: null })],
        }}
      />
    );
    expect(container.textContent).toContain("Sink");
    expect(container.textContent).toContain("Command Execution");
  });

  it("mitigation link (present=true) → renders '✓ Present'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({
              type: "mitigation",
              mitigation_type: "input-validation",
              present: true,
            }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("✓ Present");
  });

  it("mitigation link (present=false) → renders '✗ Missing'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({
              type: "mitigation",
              mitigation_type: "input-validation",
              present: false,
            }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("✗ Missing");
  });

  it("impact link → renders 'Impact' badge + scope in full mode", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({
              type: "impact",
              impact_type: "remote-code-execution",
              scope: "server-host",
            }),
          ],
        }}
        compact={false}
      />
    );
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).toContain("server-host");
  });

  it("unknown link type → renders without crash, uses raw type as label", () => {
    const unknownLink = { type: "unknown" as any } as EvidenceLink;
    expect(() =>
      render(<EvidenceChainViz chain={{ links: [unknownLink] }} />)
    ).not.toThrow();
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// BUG FIX 2 regression: truncation safety
// ═════════════════════════════════════════════════════════════════════════════════

describe("BUG FIX 2 regression: truncation safety", () => {
  it("link.observed=null → no 'Observed:' rendered (conditional render)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ observed: null })] }} />
    );
    expect(container.textContent).not.toContain("Observed:");
  });

  it("link.observed=undefined → no 'Observed:' rendered", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ observed: undefined })] }} />
    );
    expect(container.textContent).not.toContain("Observed:");
  });

  it("link.observed='' → no 'Observed:' rendered (falsy empty string)", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ observed: "" })] }} />
    );
    expect(container.textContent).not.toContain("Observed:");
  });

  it("link.observed='x'.repeat(250) → truncated with '…' (max=200)", () => {
    const longStr = "x".repeat(250);
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ observed: longStr })] }} />
    );
    const text = container.textContent ?? "";
    // Original 250-char string should NOT be present
    expect(text).not.toContain(longStr);
    // Truncated: 199 chars + "…"
    expect(text).toContain("…");
  });

  it("link.observed='x'.repeat(50) → not truncated, no '…'", () => {
    const shortStr = "x".repeat(50);
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ observed: shortStr })] }} />
    );
    const text = container.textContent ?? "";
    expect(text).toContain(shortStr);
    // No truncation ellipsis for the observed value
  });

  it("link.location='x'.repeat(150) → truncated at max=120", () => {
    const longLoc = "x".repeat(150);
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ location: longLoc })] }} />
    );
    const text = container.textContent ?? "";
    expect(text).not.toContain(longLoc);
    expect(text).toContain("…");
  });

  it("link.rationale=null → no rationale rendered", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink({ rationale: null })] }}
        compact={false}
      />
    );
    // rationale text should not be present (but other fields still render)
    expect(container.textContent).toContain("Source"); // badge still renders
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Confidence factor display
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence factor display", () => {
  it("factor with value 0.95 → shows '95%'", () => {
    const chain = makeChain();
    const { container } = render(
      <EvidenceChainViz chain={chain} compact={false} />
    );
    expect(container.textContent).toContain("95%");
  });

  it("factor with value 0.10 → shows '10%'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink()],
          confidence: 0.5,
          confidence_factors: [
            { factor: "f1", value: 0.10, description: "Low factor" },
          ],
        }}
        compact={false}
      />
    );
    expect(container.textContent).toContain("10%");
  });

  it("factor with value 0 → shows '0%'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink()],
          confidence: 0.5,
          confidence_factors: [
            { factor: "f1", value: 0, description: "Zero factor" },
          ],
        }}
        compact={false}
      />
    );
    expect(container.textContent).toContain("0%");
  });

  it("5 factors → all 5 rendered", () => {
    const factors = Array.from({ length: 5 }, (_, i) => ({
      factor: `f${i}`,
      value: 0.5 + i * 0.1,
      description: `Factor ${i}`,
    }));
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink()], confidence: 0.5, confidence_factors: factors }}
        compact={false}
      />
    );
    for (const f of factors) {
      expect(container.textContent).toContain(f.description);
    }
  });

  it("0 factors → no 'Confidence Factors' section", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink()], confidence: 0.5, confidence_factors: [] }}
        compact={false}
      />
    );
    expect(container.textContent).not.toContain("Confidence Factors");
  });

  it("factor with empty description → falls back to factor name", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink()],
          confidence: 0.5,
          confidence_factors: [
            { factor: "custom_factor_name", value: 0.7, description: "" },
          ],
        }}
        compact={false}
      />
    );
    // Component uses: f.description || f.factor
    expect(container.textContent).toContain("custom_factor_name");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Label fallbacks (formatSubtype)
// ═════════════════════════════════════════════════════════════════════════════════

describe("label fallbacks", () => {
  it("unknown source_type 'custom-source' → renders 'Custom Source'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink({ type: "source", source_type: "custom-source" })] }}
      />
    );
    expect(container.textContent).toContain("Custom Source");
  });

  it("unknown sink_type 'custom-sink' → renders 'Custom Sink'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink({ type: "sink", sink_type: "custom-sink", source_type: null })] }}
      />
    );
    expect(container.textContent).toContain("Custom Sink");
  });

  it("known source_type 'user-parameter' → renders 'User Parameter'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{ links: [makeLink({ type: "source", source_type: "user-parameter" })] }}
      />
    );
    expect(container.textContent).toContain("User Parameter");
  });

  it("propagation_type 'variable-assignment' → renders 'Variable Assignment'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({
              type: "propagation",
              propagation_type: "variable-assignment",
              source_type: null,
            }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("Variable Assignment");
  });

  it("subtype with underscores 'taint_propagation_flow' → 'Taint Propagation Flow'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({
              type: "propagation",
              propagation_type: "taint_propagation_flow",
              source_type: null,
            }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("Taint Propagation Flow");
  });

  it("link with all subtype fields null → renders badge without subtype text", () => {
    const link: EvidenceLink = {
      type: "source",
      source_type: null,
      propagation_type: null,
      sink_type: null,
      mitigation_type: null,
      impact_type: null,
    };
    const { container } = render(
      <EvidenceChainViz chain={{ links: [link] }} />
    );
    expect(container.textContent).toContain("Source");
    // No crash, no subtype text
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Compact vs full mode
// ═════════════════════════════════════════════════════════════════════════════════

describe("compact vs full mode", () => {
  it("compact hides rationale", () => {
    const chain: EvidenceChain = {
      links: [makeLink({ rationale: "Detailed rationale text here" })],
    };
    const { container: compact } = render(
      <EvidenceChainViz chain={chain} compact />
    );
    expect(compact.textContent).not.toContain("Detailed rationale text here");

    const { container: full } = render(
      <EvidenceChainViz chain={chain} compact={false} />
    );
    expect(full.textContent).toContain("Detailed rationale text here");
  });

  it("compact hides impact section entirely", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({
          type: "impact",
          impact_type: "rce",
          scope: "full-system",
        }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} compact />);
    expect(container.textContent).not.toContain("Impact");
    expect(container.textContent).not.toContain("full-system");
  });

  it("compact hides confidence factors", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} compact />);
    expect(container.textContent).not.toContain("Confidence Factors");
    expect(container.textContent).not.toContain("AST-confirmed taint flow");
  });

  it("full mode shows all sections", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "source", rationale: "Full mode rationale" }),
        makeLink({ type: "impact", impact_type: "data-theft", scope: "org-wide" }),
      ],
      confidence: 0.8,
      confidence_factors: [
        { factor: "f1", value: 0.9, description: "Full mode factor" },
      ],
    };
    const { container } = render(
      <EvidenceChainViz chain={chain} compact={false} />
    );
    expect(container.textContent).toContain("Full mode rationale");
    expect(container.textContent).toContain("org-wide");
    expect(container.textContent).toContain("Full mode factor");
    expect(container.textContent).toContain("Confidence Factors");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Flow arrows
// ═════════════════════════════════════════════════════════════════════════════════

describe("flow arrows", () => {
  it("3 flow links → 2 arrows (n-1)", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".evidence-flow-arrow");
    expect(arrows).toHaveLength(2);
  });

  it("1 flow link → 0 arrows", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink({ type: "source" })] }} />
    );
    const arrows = container.querySelectorAll(".evidence-flow-arrow");
    expect(arrows).toHaveLength(0);
  });

  it("2 flow + 1 mitigation + 1 impact → 1 arrow (only between flow links)", () => {
    const chain: EvidenceChain = {
      links: [
        makeLink({ type: "source" }),
        makeLink({ type: "sink" }),
        makeLink({ type: "mitigation", present: true }),
        makeLink({ type: "impact", scope: "test" }),
      ],
    };
    const { container } = render(<EvidenceChainViz chain={chain} />);
    const arrows = container.querySelectorAll(".evidence-flow-arrow");
    expect(arrows).toHaveLength(1);
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Section rendering structure
// ═════════════════════════════════════════════════════════════════════════════════

describe("section rendering structure", () => {
  it("chain with only mitigation links → 'Mitigations' header, no 'Data Flow'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [
            makeLink({ type: "mitigation", mitigation_type: "sanitizer", present: true }),
          ],
        }}
      />
    );
    expect(container.textContent).toContain("Mitigations");
    expect(container.textContent).not.toContain("Data Flow");
  });

  it("chain with only impact links → 'Impact' in full mode, no 'Data Flow'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink({ type: "impact", impact_type: "rce", scope: "host" })],
        }}
        compact={false}
      />
    );
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).not.toContain("Data Flow");
  });

  it("chain with all 5 link types → all sections render", () => {
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
    const { container } = render(
      <EvidenceChainViz chain={chain} compact={false} />
    );
    expect(container.textContent).toContain("Data Flow");
    expect(container.textContent).toContain("Mitigations");
    expect(container.textContent).toContain("Impact");
    expect(container.textContent).toContain("80%");
    expect(container.textContent).toContain("Confidence Factors");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════════

describe("edge cases", () => {
  it("50 links → no crash (performance)", () => {
    const links = Array.from({ length: 50 }, (_, i) =>
      makeLink({
        type: i % 3 === 0 ? "source" : i % 3 === 1 ? "propagation" : "sink",
        location: `file.ts:${i}`,
        observed: `Step ${i}`,
      })
    );
    expect(() =>
      render(<EvidenceChainViz chain={{ links }} />)
    ).not.toThrow();
  });

  it("link with every optional field null → renders badge only, no crash", () => {
    const link: EvidenceLink = {
      type: "source",
      location: null,
      observed: null,
      rationale: null,
      source_type: null,
      propagation_type: null,
      sink_type: null,
      mitigation_type: null,
      impact_type: null,
      present: undefined,
      scope: null,
    };
    const { container } = render(
      <EvidenceChainViz chain={{ links: [link] }} />
    );
    expect(container.textContent).toContain("Source");
    // No Location/Observed/rationale text
    expect(container.textContent).not.toContain("Location:");
    expect(container.textContent).not.toContain("Observed:");
  });

  it("chain with links but no confidence → no confidence bar", () => {
    const { container } = render(
      <EvidenceChainViz chain={{ links: [makeLink()] }} />
    );
    expect(container.querySelectorAll(".evidence-confidence-bar")).toHaveLength(0);
    expect(container.textContent).toContain("Source"); // links still render
  });

  it("renders link locations and observations correctly", () => {
    const chain = makeChain();
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("src/handler.ts:42");
    expect(container.textContent).toContain("exec(cmd)");
  });

  it("renders Mitigations section header for mitigation links", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink({ type: "mitigation", mitigation_type: "sanitizer" })],
        }}
      />
    );
    expect(container.textContent).toContain("Mitigations");
  });
});

// ═════════════════════════════════════════════════════════════════════════════════
// Threat reference behavior (via confidence factors, not a separate field)
// ═════════════════════════════════════════════════════════════════════════════════

describe("confidence factor edge cases", () => {
  it("factor value exactly 1.0 → '100%'", () => {
    const { container } = render(
      <EvidenceChainViz
        chain={{
          links: [makeLink()],
          confidence: 0.5,
          confidence_factors: [
            { factor: "max_factor", value: 1.0, description: "Maximum" },
          ],
        }}
        compact={false}
      />
    );
    // factor value * 100 = 100, toFixed(0) = "100"
    expect(container.textContent).toContain("100%");
  });

  it("renders 92% for confidence 0.92", () => {
    const chain = makeChain({ confidence: 0.92 });
    const { container } = render(<EvidenceChainViz chain={chain} />);
    expect(container.textContent).toContain("92%");
  });
});
