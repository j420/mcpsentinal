// @vitest-environment jsdom
/**
 * RuleEvidenceCard — three honest-rendered states + cross-ref form.
 *
 * What this guards (Cluster D part 4):
 *   1. State A (findings) — severity-tinted left border, methodology block
 *      always visible, EvidenceChainViz mounts per finding, framework
 *      cross-walk row renders for each finding.
 *   2. State B (passed)   — green check eyebrow, "PASSED" pill, methodology
 *      block visible (collapsed in <details>) — never display:none.
 *   3. State C (skipped)  — explicit "Skipped — <reason>" line, methodology
 *      block visible (collapsed in <details>), reason derived from category.
 *   4. Cross-reference   — when crossRef={true}, render only a one-line
 *      "see canonical" link to #rule-<rule_id>; no methodology, no findings.
 *
 * Rendering invariants asserted across all three states:
 *   - Anchor id="rule-<rule_id>" present
 *   - aria-label on the article
 *   - methodology block visibly present (NEVER display:none)
 *   - status pill text matches state
 *
 * Plus invariants per state:
 *   - findings: every finding mounts its own panel with a chain region
 *   - passed:  methodology in <details>, status pill = PASSED
 *   - skipped: skipped reason rendered, status pill = SKIPPED
 *   - cross-ref: deep-link href = #rule-<rule_id>
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import React from "react";
import { render, cleanup } from "@testing-library/react";

// next/navigation is consumed by the in-card <ForensicTrigger/> client
// component (added Phase 5). It throws "invariant: app router not mounted"
// when run outside Next's runtime, so stub the three hooks we use to
// satisfy the runtime check. The trigger isn't exercised by these tests
// but its hooks are evaluated whenever a finding panel renders.
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  usePathname: () => "/servers/demo",
  useSearchParams: () => new URLSearchParams(""),
}));

import RuleEvidenceCard from "../components/RuleEvidenceCard";
import type {
  DeepDiveRule,
  DeepDiveFinding,
  DeepDiveFrameworkControl,
} from "../lib/deep-dive";

// ── Helpers ─────────────────────────────────────────────────────────────

const FIXED_NOW = new Date("2026-05-01T12:00:00.000Z").getTime();

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(FIXED_NOW);
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

const FW_CONTROLS: DeepDiveFrameworkControl[] = [
  { framework_id: "owasp_mcp", control_id: "MCP01", control_title: "Prompt Injection" },
  { framework_id: "mitre_atlas", control_id: "AML.T0054.001", control_title: "Indirect Prompt Injection" },
];

function baseRule(overrides: Partial<DeepDiveRule> = {}): DeepDiveRule {
  return {
    rule_id: "G1",
    name: "Indirect Prompt Injection Gateway",
    severity: "critical",
    category: "adversarial-ai",
    owasp: "MCP01",
    mitre: "AML.T0054.001",
    summary:
      "Detects MCP servers that ingest external content and pass it to the LLM without trust-boundary tagging.",
    framework_controls: FW_CONTROLS,
    methodology: {
      technique: "capability-graph + linguistic scoring",
      verified_edge_cases: [
        "Slack thread history returned verbatim",
        "RAG retrieval from attacker-poisoned web corpus",
        "Email body returned without trust-boundary tag",
      ],
      edge_case_strategies: [],
      confidence_cap: null,
    },
    backing: {
      cve_replay_ids: ["CVE-2024-12345", "CVE-2024-99999"],
      fixture_count: 14,
      precision: 0.92,
      recall: 0.86,
      last_validated_at: "2026-04-30T09:00:00.000Z",
    },
    remediation:
      "Tag all data ingested from external sources and refuse to interpolate it into prompts without the tag.",
    status: "findings",
    findings: [],
    ...overrides,
  };
}

function makeFinding(
  id: string,
  overrides: Partial<DeepDiveFinding> = {},
): DeepDiveFinding {
  return {
    id,
    severity: "critical",
    evidence: "Slack thread history is returned verbatim through the read_channel_messages tool.",
    remediation: "Wrap returned thread bodies in a TRUSTED_BOUNDARY block.",
    confidence: 0.91,
    evidence_chain: null,
    // Cluster D reviewer B5 — `framework_controls` lives on the parent
    // rule, not per-finding. Removed.
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────────

describe("RuleEvidenceCard — invariants across states", () => {
  it("renders the rule_id anchor on every state (findings)", () => {
    const rule = baseRule({ status: "findings", findings: [makeFinding("f-1")] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const article = container.querySelector("#rule-G1");
    expect(article).not.toBeNull();
    expect(article?.tagName).toBe("ARTICLE");
  });

  it("renders the rule_id anchor on every state (passed)", () => {
    const rule = baseRule({ status: "passed", findings: [] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    expect(container.querySelector("#rule-G1")).not.toBeNull();
  });

  it("renders the rule_id anchor on every state (skipped)", () => {
    const rule = baseRule({ status: "skipped", findings: [], category: "code-analysis" });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    expect(container.querySelector("#rule-G1")).not.toBeNull();
  });

  it("carries an aria-label on the article (all three states)", () => {
    for (const status of ["findings", "passed", "skipped"] as const) {
      const findings = status === "findings" ? [makeFinding("f-1")] : [];
      const rule = baseRule({ status, findings, category: "code-analysis" });
      const { container, unmount } = render(<RuleEvidenceCard rule={rule} />);
      const article = container.querySelector("#rule-G1");
      expect(article?.getAttribute("aria-label") ?? "").toMatch(/G1/);
      unmount();
    }
  });
});

describe("RuleEvidenceCard — STATE A: findings", () => {
  it("renders a severity-tinted card with critical token style", () => {
    const rule = baseRule({ status: "findings", findings: [makeFinding("f-1")] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const card = container.querySelector(".rec-card-findings");
    expect(card).not.toBeNull();
    // The severity class drives the per-token border colour.
    expect(card?.classList.contains("rec-sev-critical")).toBe(true);
    // The severity CSS variable is applied via inline style.
    const styleAttr = (card as HTMLElement | null)?.getAttribute("style") ?? "";
    expect(styleAttr).toMatch(/--rec-sev-color/);
  });

  it("renders the methodology block VISIBLY (not in <details>) for findings", () => {
    const rule = baseRule({ status: "findings", findings: [makeFinding("f-1")] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const method = container.querySelector(".rec-method");
    expect(method).not.toBeNull();
    // findings state uses a <section>, NOT a <details>, so it stays open.
    expect(method?.tagName).toBe("SECTION");
  });

  it("mounts an EvidenceChainViz region per finding (independent per finding)", () => {
    const rule = baseRule({
      status: "findings",
      findings: [
        makeFinding("f-1", {
          evidence_chain: {
            links: [
              {
                type: "source",
                source_type: "external-content",
                location: "src/slack.ts:42",
                observed: "channel.history",
                rationale: "Slack channel history is treated as trusted by downstream prompt template.",
              },
            ],
            confidence_factors: [],
            confidence: 0.9,
          },
        }),
        makeFinding("f-2", {
          evidence_chain: null,
          confidence: 0.4,
        }),
      ],
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    // Two finding panels — each their own <details> with a unique anchor id.
    const panels = container.querySelectorAll(".rec-finding");
    expect(panels.length).toBe(2);
    expect(container.querySelector("#finding-G1-f-1")).not.toBeNull();
    expect(container.querySelector("#finding-G1-f-2")).not.toBeNull();
    // Finding 1 has the chain → ec5-report renders. Finding 2 has only
    // confidence → ec5-confidence-only renders. Either way, there's a
    // distinct evidence region per finding.
    expect(container.querySelectorAll(".ec5-report").length + container.querySelectorAll(".ec5-confidence-only").length).toBeGreaterThanOrEqual(2);
  });

  it("renders the framework cross-walk at the rule level (not duplicated per finding)", () => {
    // Cluster D reviewer B5 lesson — `framework_controls` lives on the
    // parent rule, not duplicated per finding (DeepDiveFinding has no
    // framework_controls field per the canonical DB schema). The
    // rule-level methodology block renders the cross-walk; the per-
    // finding sub-card no longer does.
    const rule = baseRule({
      status: "findings",
      findings: [makeFinding("f-1")],
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    // Rule-level Frameworks block in the methodology dl.
    const fwBlock = container.querySelector(".rec-fw-list");
    expect(fwBlock).not.toBeNull();
    expect(fwBlock?.textContent ?? "").toMatch(/OWASP MCP/);
    // No duplicate per-finding fw block.
    const perFinding = container.querySelector(".rec-finding-fw");
    expect(perFinding).toBeNull();
  });
});

describe("RuleEvidenceCard — STATE B: passed", () => {
  it("renders the PASSED status pill and the green eyebrow", () => {
    const rule = baseRule({ status: "passed", findings: [] });
    const { container, getByText } = render(<RuleEvidenceCard rule={rule} />);
    expect(getByText(/^PASSED$/)).not.toBeNull();
    const eyebrow = container.querySelector(".rec-eyebrow-passed");
    expect(eyebrow).not.toBeNull();
  });

  it("renders methodology inside <details> (collapsed), VISIBLY", () => {
    const rule = baseRule({ status: "passed", findings: [] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const method = container.querySelector(".rec-method");
    expect(method).not.toBeNull();
    expect(method?.tagName).toBe("DETAILS");
    // Methodology summary line ALWAYS visible — it's the <summary> element,
    // which is the part of <details> that renders when collapsed.
    const summary = method?.querySelector("summary");
    expect(summary).not.toBeNull();
    expect(summary?.textContent ?? "").toMatch(/capability-graph/);
  });

  it("renders the methodology summary one-liner (technique + backing)", () => {
    const rule = baseRule({ status: "passed", findings: [] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const summaryText = container.querySelector(".rec-method-summary")?.textContent ?? "";
    expect(summaryText).toMatch(/capability-graph/);
    expect(summaryText).toMatch(/14 fixtures/);
    expect(summaryText).toMatch(/precision 0\.92/);
  });

  it("does NOT render any finding panels (passed → no findings)", () => {
    const rule = baseRule({ status: "passed", findings: [] });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    expect(container.querySelectorAll(".rec-finding").length).toBe(0);
    expect(container.querySelector(".rec-findings")).toBeNull();
  });
});

describe("RuleEvidenceCard — STATE C: skipped", () => {
  it("renders the SKIPPED status pill and the muted eyebrow", () => {
    const rule = baseRule({
      status: "skipped",
      findings: [],
      category: "code-analysis",
    });
    const { container, getByText } = render(<RuleEvidenceCard rule={rule} />);
    expect(getByText(/^SKIPPED$/)).not.toBeNull();
    const eyebrow = container.querySelector(".rec-eyebrow-skipped");
    expect(eyebrow).not.toBeNull();
  });

  it("renders the explicit skip reason derived from category", () => {
    const rule = baseRule({
      status: "skipped",
      findings: [],
      category: "code-analysis",
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const reason = container.querySelector("[data-rec-skip-reason]");
    expect(reason).not.toBeNull();
    expect(reason?.textContent ?? "").toMatch(/Skipped/i);
    expect(reason?.textContent ?? "").toMatch(/source code/i);
  });

  it("renders methodology in <details> (visibly, never silently absent)", () => {
    const rule = baseRule({
      status: "skipped",
      findings: [],
      category: "dependency-analysis",
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const method = container.querySelector(".rec-method");
    expect(method).not.toBeNull();
    expect(method?.tagName).toBe("DETAILS");
    // The methodology summary line stays visible (it's the <summary> child).
    expect(method?.querySelector("summary")).not.toBeNull();
  });

  it("derives a category-specific reason for dependency-analysis", () => {
    const rule = baseRule({
      status: "skipped",
      findings: [],
      category: "dependency-analysis",
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const reason = container.querySelector("[data-rec-skip-reason]");
    expect(reason?.textContent ?? "").toMatch(/package manifest/i);
  });
});

describe("RuleEvidenceCard — cross-reference mode", () => {
  it("renders only the one-line link, no full card body", () => {
    const rule = baseRule({ status: "findings", findings: [makeFinding("f-1")] });
    const { container } = render(<RuleEvidenceCard rule={rule} crossRef={true} />);
    expect(container.querySelector(".rec-xref")).not.toBeNull();
    // No methodology, no findings stack, no rule body.
    expect(container.querySelector(".rec-card")).toBeNull();
    expect(container.querySelector(".rec-method")).toBeNull();
    expect(container.querySelector(".rec-finding")).toBeNull();
  });

  it("links to #rule-<rule_id> as the canonical anchor", () => {
    const rule = baseRule();
    const { container } = render(<RuleEvidenceCard rule={rule} crossRef={true} />);
    const link = container.querySelector(".rec-xref-link") as HTMLAnchorElement | null;
    expect(link).not.toBeNull();
    expect(link?.getAttribute("href")).toBe("#rule-G1");
  });

  it("carries a descriptive aria-label", () => {
    const rule = baseRule();
    const { container } = render(<RuleEvidenceCard rule={rule} crossRef={true} />);
    const wrap = container.querySelector(".rec-xref");
    expect(wrap?.getAttribute("aria-label") ?? "").toMatch(/Cross-reference.*G1/);
  });
});

describe("RuleEvidenceCard — methodology gap honesty", () => {
  // Phase 1.4c — backing now distinguishes two empty states:
  //   1. backing == null         → "validation corpus not yet wired"
  //   2. backing all-empty fields → "no validation runs on file yet"
  // The previous single "no backing data wired yet" copy collapsed both;
  // the regulator-grade UX requires the two states to render distinctly so
  // a reader knows which gap is OURS vs which is the validation team's.

  it("renders 'no validation runs on file' when backing is wired but empty", () => {
    const rule = baseRule({
      status: "passed",
      findings: [],
      backing: {
        cve_replay_ids: [],
        fixture_count: 0,
        precision: null,
        recall: null,
        last_validated_at: null,
      },
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const summary = container.querySelector(".rec-method-summary")?.textContent ?? "";
    expect(summary).toMatch(/no validation runs on file yet/);
    // The collapsed body should also surface the structured data-attribute
    // so a downstream test or CSS rule can target the empty state directly.
    const bodyGap = container.querySelector("[data-rec-backing-state]");
    expect(bodyGap?.getAttribute("data-rec-backing-state")).toBe("wired_no_runs");
  });

  it("renders 'validation corpus not yet wired' when backing is null", () => {
    const rule = baseRule({
      status: "passed",
      findings: [],
      backing: null,
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const summary = container.querySelector(".rec-method-summary")?.textContent ?? "";
    expect(summary).toMatch(/validation corpus not yet wired/);
    const bodyGap = container.querySelector("[data-rec-backing-state]");
    expect(bodyGap?.getAttribute("data-rec-backing-state")).toBe("not_wired");
  });

  it("renders 'technique not declared' when methodology technique is empty", () => {
    const rule = baseRule({
      status: "passed",
      findings: [],
      methodology: {
        technique: "",
        verified_edge_cases: [],
        edge_case_strategies: [],
        confidence_cap: null,
      },
    });
    const { container } = render(<RuleEvidenceCard rule={rule} />);
    const summary = container.querySelector(".rec-method-summary")?.textContent ?? "";
    expect(summary).toMatch(/technique not declared/);
  });
});
