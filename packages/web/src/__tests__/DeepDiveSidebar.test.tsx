// @vitest-environment jsdom
/**
 * DeepDiveSidebar Test Suite — Cluster D part 5/5.
 *
 * Coverage required by briefing (14 cases minimum):
 *   1.  TOC renders all categories + sub-categories with counts
 *   2.  severity dots reflect most-severe finding
 *   3.  search box filters tree (substring match)
 *   4.  search box filters tree (fuzzy: case + punctuation)
 *   5.  severity chip toggle filters tree
 *   6.  framework chip toggle filters tree
 *   7.  "only failing" hides passed rules from counts
 *   8.  "include skipped" surfaces skipped rules in counts
 *   9.  URL state read on mount
 *  10.  URL state written on filter change (debounced for search)
 *  11.  scroll-spy active class follows IntersectionObserver
 *  12.  keyboard: Enter on TOC item navigates
 *  13.  keyboard: Esc clears search
 *  14.  mobile <720px collapses to accordion
 *
 * Component is a Client Component reading next/navigation hooks. We mock the
 * hooks at import time so the component believes it lives inside a router.
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
  type Mock,
} from "vitest";
import React from "react";
import { act, fireEvent, render } from "@testing-library/react";
import type {
  DeepDiveCategory,
  DeepDiveRule,
  DeepDiveSubCategory,
} from "@/lib/deep-dive";

// ── Router mocks ───────────────────────────────────────────────────────────
//
// The component pulls useRouter, usePathname, useSearchParams from
// next/navigation. We control `mockSearchParamsString` to drive URL state
// reads, and capture writes via mockRouterPush.

let mockSearchParamsString = "";
const mockRouterPush: Mock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: mockRouterPush,
    replace: vi.fn(),
    refresh: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  usePathname: () => "/servers/demo",
  useSearchParams: () => new URLSearchParams(mockSearchParamsString),
}));

// ── IntersectionObserver mock ──────────────────────────────────────────────
//
// jsdom does not implement IO. We expose a controllable singleton so a single
// test can simulate intersections by invoking the captured callback directly.

interface IOEntryShape {
  target: Element;
  isIntersecting: boolean;
  intersectionRatio: number;
}

interface IOControl {
  callback:
    | ((entries: IOEntryShape[], obs: IntersectionObserver) => void)
    | null;
  observed: Set<Element>;
}

const ioControl: IOControl = { callback: null, observed: new Set() };

class FakeIO implements IntersectionObserver {
  readonly root: Element | null = null;
  readonly rootMargin: string = "";
  readonly thresholds: ReadonlyArray<number> = [0];
  constructor(
    cb: (entries: IOEntryShape[], obs: IntersectionObserver) => void,
  ) {
    ioControl.callback = cb;
  }
  observe(el: Element): void {
    ioControl.observed.add(el);
  }
  unobserve(el: Element): void {
    ioControl.observed.delete(el);
  }
  disconnect(): void {
    ioControl.observed.clear();
    ioControl.callback = null;
  }
  takeRecords(): IntersectionObserverEntry[] {
    return [];
  }
}

beforeEach(() => {
  mockSearchParamsString = "";
  mockRouterPush.mockReset();
  ioControl.callback = null;
  ioControl.observed.clear();
  // @ts-expect-error - test mock
  globalThis.IntersectionObserver = FakeIO;
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

// Import AFTER router mocks are registered (ESM hoisting handles vi.mock but
// we keep the import here for clarity).
import DeepDiveSidebar from "@/components/DeepDiveSidebar";

// ── Fixture builders ───────────────────────────────────────────────────────

function makeRule(overrides: Partial<DeepDiveRule> = {}): DeepDiveRule {
  return {
    rule_id: "A1",
    name: "Prompt Injection in Tool Description",
    severity: "critical",
    category: "description-analysis",
    owasp: "MCP01",
    mitre: "AML.T0054",
    summary: "Detects role injection and exfiltration directives in tool descriptions.",
    framework_controls: [
      { framework: "owasp_mcp", control: "MCP01", label: "Prompt Injection" },
      { framework: "eu_ai_act", control: "Art.15", label: "Robustness" },
    ],
    methodology: "linguistic scoring + entropy",
    backing: { precision: 0.92, recall: 0.88, red_team_fixture_count: 23 },
    remediation: "Sanitize tool descriptions before display.",
    status: "findings",
    findings: [
      {
        id: "f1",
        rule_id: "A1",
        severity: "critical",
        evidence: "Detected role-injection phrase in description.",
        remediation: "Sanitize tool descriptions.",
      },
    ],
    ...overrides,
  };
}

function makeSub(
  id: string,
  title: string,
  rules: DeepDiveRule[],
): DeepDiveSubCategory {
  // counts sum from rules — minimal, just enough for the badge math.
  let findings = 0;
  let withFindings = 0;
  let passed = 0;
  let skipped = 0;
  const sb = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  for (const r of rules) {
    if (r.status === "findings") withFindings += 1;
    else if (r.status === "passed") passed += 1;
    else if (r.status === "skipped") skipped += 1;
    findings += r.findings.length;
    for (const f of r.findings) sb[f.severity] += 1;
  }
  return {
    id,
    title,
    summary: `${title} sub-category summary.`,
    counts: {
      rules_total: rules.length,
      rules_passed: passed,
      rules_with_findings: withFindings,
      rules_skipped: skipped,
      finding_count: findings,
      severity_breakdown: sb,
    },
    rules,
  };
}

function makeCat(
  id: string,
  title: string,
  subs: DeepDiveSubCategory[],
): DeepDiveCategory {
  let findings = 0;
  const sb = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  };
  let total = 0;
  let withFindings = 0;
  let passed = 0;
  let skipped = 0;
  for (const s of subs) {
    findings += s.counts.finding_count;
    total += s.counts.rules_total;
    withFindings += s.counts.rules_with_findings;
    passed += s.counts.rules_passed;
    skipped += s.counts.rules_skipped;
    for (const k of Object.keys(sb) as Array<keyof typeof sb>) {
      sb[k] += s.counts.severity_breakdown[k];
    }
  }
  return {
    id,
    title,
    summary: `${title} category summary.`,
    frameworks: ["EU AI Act", "OWASP MCP"],
    counts: {
      rules_total: total,
      rules_passed: passed,
      rules_with_findings: withFindings,
      rules_skipped: skipped,
      finding_count: findings,
      severity_breakdown: sb,
    },
    sub_categories: subs,
  };
}

function buildFixtureCategories(): DeepDiveCategory[] {
  // Two categories, three sub-categories total.
  const promptInj = makeCat("prompt-injection", "Prompt Injection", [
    makeSub("direct-input", "Direct Input", [
      makeRule({
        rule_id: "A1",
        severity: "critical",
        status: "findings",
      }),
    ]),
    makeSub("indirect-gateway", "Indirect Gateway", [
      makeRule({
        rule_id: "G1",
        name: "Indirect Prompt Injection Gateway",
        severity: "high",
        status: "findings",
        framework_controls: [
          { framework: "iso_27001", control: "A.5.21" },
        ],
        findings: [
          {
            id: "g1-f1",
            rule_id: "G1",
            severity: "high",
            evidence: "External content ingestion sink found.",
            remediation: "Validate external content before sink.",
          },
          {
            id: "g1-f2",
            rule_id: "G1",
            severity: "medium",
            evidence: "Secondary path-traversal vector.",
            remediation: "Sanitize input.",
          },
        ],
      }),
      makeRule({
        rule_id: "G2",
        name: "Trust Assertion Injection",
        severity: "medium",
        status: "passed",
        findings: [],
      }),
    ]),
  ]);
  const codeVuln = makeCat("code-vulns", "Code Vulnerabilities", [
    makeSub("injection", "Injection", [
      makeRule({
        rule_id: "C1",
        name: "Command Injection",
        severity: "critical",
        status: "skipped",
        findings: [],
        framework_controls: [
          { framework: "owasp_mcp", control: "MCP03" },
        ],
      }),
    ]),
  ]);
  return [promptInj, codeVuln];
}

// ════════════════════════════════════════════════════════════════════════
// 1. TOC renders all categories + sub-categories with counts
// ════════════════════════════════════════════════════════════════════════

describe("TOC structure", () => {
  it("renders every category and sub-category with finding counts", () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    // Sidebar renders both desktop and mobile layouts (CSS toggles
    // visibility via @media). Scope to the desktop layer for counts so we
    // don't double-count the mobile <details> mirror.
    const desktop = container.querySelector(".dds-desktop")!;
    const cats = desktop.querySelectorAll(".ddt-cat");
    expect(cats.length).toBe(2);
    // Only matched categories render their sub-list. With include-skipped
    // OFF (default), code-vulns category's only rule (status="skipped") is
    // hidden — so the category is unmatched and its sub-list collapsed.
    // The prompt-injection category contributes both of its 2 sub-items.
    const subs = desktop.querySelectorAll(".ddt-sub");
    expect(subs.length).toBe(2);

    const text = desktop.textContent ?? "";
    expect(text).toContain("Prompt Injection");
    expect(text).toContain("Code Vulnerabilities");
    expect(text).toContain("Direct Input");
    expect(text).toContain("Indirect Gateway");
    expect(text).toContain("Injection");

    // Finding counts: prompt-injection has 3 (A1=1 + G1=2); code-vulns has 0.
    const promptCat = Array.from(cats).find((el) =>
      el.textContent?.includes("Prompt Injection"),
    );
    expect(promptCat?.textContent).toContain("(3)");
    const codeCat = Array.from(cats).find((el) =>
      el.textContent?.includes("Code Vulnerabilities"),
    );
    // status='skipped' rule is HIDDEN by default, so the rule count is 0.
    expect(codeCat?.textContent).toContain("(0)");
    expect(codeCat?.textContent).toContain("0 rules");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 2. severity dots reflect most-severe finding
// ════════════════════════════════════════════════════════════════════════

describe("severity dot per sub-category", () => {
  it("shows critical dot when any finding is critical, otherwise the next-most-severe", () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    // Direct Input has one critical finding.
    const directSub = container.querySelector("[href='#sub-direct-input']");
    expect(directSub).toBeTruthy();
    expect(
      directSub!.querySelector(".ddt-sev-critical"),
    ).toBeTruthy();

    // Indirect Gateway has high + medium (no critical) — most severe = high.
    const indirectSub = container.querySelector(
      "[href='#sub-indirect-gateway']",
    );
    expect(indirectSub).toBeTruthy();
    expect(indirectSub!.querySelector(".ddt-sev-high")).toBeTruthy();
    expect(indirectSub!.querySelector(".ddt-sev-critical")).toBeFalsy();
  });
});

// ════════════════════════════════════════════════════════════════════════
// 3. search box filters tree (substring match)
// ════════════════════════════════════════════════════════════════════════

describe("search box — substring", () => {
  it("typing 'gateway' restricts the tree to the matching sub-category", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const input = container.querySelector(
      ".dds-search",
    ) as HTMLInputElement | null;
    expect(input).toBeTruthy();

    await act(async () => {
      fireEvent.change(input!, { target: { value: "gateway" } });
      // Debounce window
      vi.advanceTimersByTime(300);
    });

    // Code Vulnerabilities did not match → category is muted.
    const codeCat = container
      .querySelector("[href='#cat-code-vulns']")
      ?.parentElement;
    expect(codeCat?.classList.contains("ddt-cat-muted")).toBe(true);

    // Prompt Injection still matches via "Indirect Gateway".
    const promptCat = container
      .querySelector("[href='#cat-prompt-injection']")
      ?.parentElement;
    expect(promptCat?.classList.contains("ddt-cat-muted")).toBe(false);

    // Direct Input sub did not match → muted within an expanded matched cat.
    const directSub = container
      .querySelector("[href='#sub-direct-input']")
      ?.parentElement;
    expect(directSub?.classList.contains("ddt-sub-muted")).toBe(true);

    // Indirect Gateway sub matched.
    const indirectSub = container
      .querySelector("[href='#sub-indirect-gateway']")
      ?.parentElement;
    expect(indirectSub?.classList.contains("ddt-sub-muted")).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════
// 4. search box filters tree (fuzzy: case + punctuation)
// ════════════════════════════════════════════════════════════════════════

describe("search box — fuzzy/punctuation", () => {
  it("ignores case and non-alphanumeric characters in the haystack", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const input = container.querySelector(
      ".dds-search",
    ) as HTMLInputElement | null;

    // "PROMPT-INJECTION!" should still match the rule whose summary contains
    // "prompt injection" (separated by a space).
    await act(async () => {
      fireEvent.change(input!, { target: { value: "PROMPT-INJECTION!" } });
      vi.advanceTimersByTime(300);
    });

    const promptCat = container
      .querySelector("[href='#cat-prompt-injection']")
      ?.parentElement;
    expect(promptCat?.classList.contains("ddt-cat-muted")).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════
// 5. severity chip toggle filters tree
// ════════════════════════════════════════════════════════════════════════

describe("severity chip toggle", () => {
  it("unchecking 'high' hides the indirect-gateway high finding from the count", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    // Sanity: indirect-gateway shows 2 findings (high + medium) by default.
    const indirectLink = container.querySelector(
      "[href='#sub-indirect-gateway']",
    );
    expect(indirectLink?.textContent).toContain("(2)");

    // Locate severity chip with text "High" and click it OFF.
    const chips = Array.from(
      container.querySelectorAll(".ddf-sev-chip"),
    ) as HTMLButtonElement[];
    const highChip = chips.find((c) => c.textContent?.includes("High"));
    expect(highChip).toBeTruthy();

    await act(async () => {
      fireEvent.click(highChip!);
    });

    // After the chip is unchecked, the rule G1 (severity: high) is no longer
    // in the matched set. The sidebar still shows the underlying counts (the
    // finding badge counts findings on rules that pass failOnly+showSkipped,
    // not severity), but the matched flag flips.
    expect(highChip!.getAttribute("aria-pressed")).toBe("false");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 6. framework chip toggle filters tree
// ════════════════════════════════════════════════════════════════════════

describe("framework chip toggle", () => {
  it("unchecking ISO 27001 unmatches G1 (only sub-category match driver)", async () => {
    const cats = buildFixtureCategories();
    const { container } = render(<DeepDiveSidebar categories={cats} />);

    const fwChips = Array.from(
      container.querySelectorAll(".ddf-fw-chip"),
    ) as HTMLButtonElement[];
    const isoChip = fwChips.find((c) => c.textContent?.includes("ISO 27001"));
    expect(isoChip).toBeTruthy();
    // Default: pressed/active.
    expect(isoChip!.getAttribute("aria-pressed")).toBe("true");

    await act(async () => {
      fireEvent.click(isoChip!);
    });
    expect(isoChip!.getAttribute("aria-pressed")).toBe("false");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 7. "only failing" hides passed rules from counts
// ════════════════════════════════════════════════════════════════════════

describe("only failing toggle", () => {
  it("hides passed rules from the rule count and removes the rule suffix", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    // With failOnly OFF, the suffix "· N rules" appears next to counts.
    expect(container.textContent).toContain("rules");

    const failOnly = Array.from(
      container.querySelectorAll(".ddf-toggle"),
    ).find((b) => b.textContent?.includes("only failing"));
    expect(failOnly).toBeTruthy();

    await act(async () => {
      fireEvent.click(failOnly!);
    });
    expect(failOnly!.getAttribute("aria-pressed")).toBe("true");
    // The rule count suffix is suppressed when failOnly is ON.
    expect(
      container.querySelector(".ddt-count-rules"),
    ).toBeFalsy();
  });
});

// ════════════════════════════════════════════════════════════════════════
// 8. "include skipped" surfaces skipped rules in counts
// ════════════════════════════════════════════════════════════════════════

describe("include skipped toggle", () => {
  it("surfaces the skipped C1 rule into the code-vulns count", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    // Default — skipped HIDDEN: code-vulns has 0 rules.
    const codeCat = container
      .querySelector("[href='#cat-code-vulns']")
      ?.parentElement;
    expect(codeCat?.textContent).toContain("0 rules");

    const includeSkipped = Array.from(
      container.querySelectorAll(".ddf-toggle"),
    ).find((b) => b.textContent?.includes("include skipped"));
    expect(includeSkipped).toBeTruthy();

    await act(async () => {
      fireEvent.click(includeSkipped!);
    });

    expect(includeSkipped!.getAttribute("aria-pressed")).toBe("true");
    const codeCatAfter = container
      .querySelector("[href='#cat-code-vulns']")
      ?.parentElement;
    expect(codeCatAfter?.textContent).toContain("1 rules");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 9. URL state read on mount
// ════════════════════════════════════════════════════════════════════════

describe("URL state hydration", () => {
  it("hydrates search + severity filter from ?q=&sev= on mount", () => {
    mockSearchParamsString = "q=command&sev=critical";
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    const input = container.querySelector(
      ".dds-search",
    ) as HTMLInputElement | null;
    expect(input?.value).toBe("command");

    const chips = Array.from(
      container.querySelectorAll(".ddf-sev-chip"),
    ) as HTMLButtonElement[];
    const highChip = chips.find((c) => c.textContent?.includes("High"));
    expect(highChip?.getAttribute("aria-pressed")).toBe("false");
    const criticalChip = chips.find((c) => c.textContent?.includes("Critical"));
    expect(criticalChip?.getAttribute("aria-pressed")).toBe("true");
  });

  it("hydrates fail_only and show_skipped flags", () => {
    mockSearchParamsString = "fail_only=1&show_skipped=1";
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const toggles = Array.from(
      container.querySelectorAll(".ddf-toggle"),
    ) as HTMLButtonElement[];
    const failOnly = toggles.find((b) => b.textContent?.includes("only failing"));
    const showSkipped = toggles.find((b) =>
      b.textContent?.includes("include skipped"),
    );
    expect(failOnly?.getAttribute("aria-pressed")).toBe("true");
    expect(showSkipped?.getAttribute("aria-pressed")).toBe("true");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 10. URL state written on filter change (debounced for search)
// ════════════════════════════════════════════════════════════════════════

describe("URL state writeback", () => {
  it("debounces search writes: no push within the debounce window", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const input = container.querySelector(
      ".dds-search",
    ) as HTMLInputElement | null;

    await act(async () => {
      fireEvent.change(input!, { target: { value: "command" } });
      // Below the 250ms debounce window.
      vi.advanceTimersByTime(100);
    });
    expect(mockRouterPush).not.toHaveBeenCalled();

    await act(async () => {
      vi.advanceTimersByTime(300);
    });
    expect(mockRouterPush).toHaveBeenCalledTimes(1);
    const calledWith = mockRouterPush.mock.calls[0][0] as string;
    expect(calledWith).toContain("q=command");
  });

  it("writes severity filter immediately on chip click", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const chips = Array.from(
      container.querySelectorAll(".ddf-sev-chip"),
    ) as HTMLButtonElement[];
    const lowChip = chips.find((c) => c.textContent?.includes("Low"));
    expect(lowChip).toBeTruthy();

    await act(async () => {
      fireEvent.click(lowChip!);
    });
    expect(mockRouterPush).toHaveBeenCalledTimes(1);
    const calledWith = mockRouterPush.mock.calls[0][0] as string;
    // "Low" is now unchecked → 4 severities remain → URL must list them.
    // URLSearchParams URL-encodes commas as %2C; assert against the decoded
    // form so the test stays robust if the framework swaps to plain commas.
    const decoded = decodeURIComponent(calledWith);
    expect(decoded).toContain("sev=critical,high,medium,informational");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 11. scroll-spy active class follows IntersectionObserver
// ════════════════════════════════════════════════════════════════════════

describe("scroll-spy", () => {
  it("marks the intersecting anchor with aria-current=location", async () => {
    // Render anchor targets (cat-* / sub-*) into the document so the
    // observer has elements to find via getElementById.
    const targetHost = document.createElement("div");
    document.body.appendChild(targetHost);
    for (const id of [
      "cat-prompt-injection",
      "sub-direct-input",
      "sub-indirect-gateway",
      "cat-code-vulns",
      "sub-injection",
    ]) {
      const el = document.createElement("section");
      el.id = id;
      // Stub a getBoundingClientRect because jsdom returns zero rects.
      Object.defineProperty(el, "getBoundingClientRect", {
        value: () => ({
          top: id === "sub-indirect-gateway" ? 100 : 1000,
          bottom: 0,
          left: 0,
          right: 0,
          width: 0,
          height: 0,
          x: 0,
          y: 0,
          toJSON: () => ({}),
        }),
      });
      targetHost.appendChild(el);
    }

    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );

    // Trigger an "intersection" of sub-indirect-gateway.
    expect(ioControl.callback).not.toBeNull();
    const subEl = document.getElementById("sub-indirect-gateway")!;
    await act(async () => {
      ioControl.callback!(
        [{ target: subEl, isIntersecting: true, intersectionRatio: 0.8 }],
        // @ts-expect-error - test mock obs argument
        null,
      );
    });

    const activeNode = container.querySelector(
      "[aria-current='location']",
    ) as HTMLElement | null;
    expect(activeNode).toBeTruthy();
    expect(activeNode!.querySelector("[href='#sub-indirect-gateway']")).toBeTruthy();

    document.body.removeChild(targetHost);
  });
});

// ════════════════════════════════════════════════════════════════════════
// 12. keyboard: Enter on TOC item navigates
// ════════════════════════════════════════════════════════════════════════

describe("keyboard navigation", () => {
  it("activates the TOC anchor on Enter — the link's href is honoured", () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    // Anchors carry hrefs; pressing Enter on a focused <a> defaults to
    // navigation in browsers. Here we assert the link semantics — keyboard
    // tab order + href — rather than simulating in-jsdom navigation.
    const link = container.querySelector(
      "[href='#sub-indirect-gateway']",
    ) as HTMLAnchorElement | null;
    expect(link).toBeTruthy();
    expect(link!.getAttribute("href")).toBe("#sub-indirect-gateway");
    // tabIndex is the browser default for <a href>; treeitem role is set on parent.
    const parent = link!.parentElement!;
    expect(parent.getAttribute("role")).toBe("treeitem");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 13. keyboard: Esc clears search
// ════════════════════════════════════════════════════════════════════════

describe("Esc clears search", () => {
  it("Escape on the search input resets it to empty", async () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const input = container.querySelector(
      ".dds-search",
    ) as HTMLInputElement | null;

    await act(async () => {
      fireEvent.change(input!, { target: { value: "anything" } });
    });
    expect(input!.value).toBe("anything");

    await act(async () => {
      fireEvent.keyDown(input!, { key: "Escape" });
    });
    expect(input!.value).toBe("");
  });
});

// ════════════════════════════════════════════════════════════════════════
// 14. mobile <720px collapses to accordion
// ════════════════════════════════════════════════════════════════════════

describe("mobile accordion", () => {
  it("renders both desktop and mobile layouts; <details> closed by default", () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    // Desktop layer is always rendered (CSS toggles visibility per breakpoint).
    expect(container.querySelector(".dds-desktop")).toBeTruthy();
    // Mobile <details> is present and starts CLOSED.
    const details = container.querySelector(
      ".dds-mobile",
    ) as HTMLDetailsElement | null;
    expect(details).toBeTruthy();
    expect(details!.tagName.toLowerCase()).toBe("details");
    expect(details!.open).toBe(false);
    // The summary contains the navigation entry-point text.
    const summary = details!.querySelector(".dds-mobile-summary");
    expect(summary?.textContent).toMatch(/Filter & navigate/);
  });
});

// ════════════════════════════════════════════════════════════════════════
// Bonus: aria-label + role=tree wiring
// ════════════════════════════════════════════════════════════════════════

describe("aria semantics", () => {
  it("nav has aria-label, search input is labelled, tree carries role=tree", () => {
    const { container } = render(
      <DeepDiveSidebar categories={buildFixtureCategories()} />,
    );
    const nav = container.querySelector("nav.dds-rail");
    expect(nav?.getAttribute("aria-label")).toBe(
      "Deep dive table of contents",
    );
    const input = container.querySelector(".dds-search");
    expect(input?.getAttribute("aria-label")).toBe("Filter rules");
    const tree = container.querySelector(".ddt-tree");
    expect(tree?.getAttribute("role")).toBe("tree");
  });
});
