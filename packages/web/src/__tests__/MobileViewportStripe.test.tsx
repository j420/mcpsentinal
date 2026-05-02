// @vitest-environment jsdom
/**
 * MobileViewportStripe tests.
 *
 * Guards: stripe renders only when at least one finding exists, picks
 * the worst severity present, and survives partial / malformed
 * coverage shapes without throwing.
 */

import { afterEach, describe, expect, it } from "vitest";
import React from "react";
import { cleanup, render } from "@testing-library/react";
import MobileViewportStripe from "@/components/MobileViewportStripe";
import type { DeepDiveCoverageSummary } from "@/lib/deep-dive";

afterEach(() => cleanup());

function makeCoverage(
  overrides: Partial<DeepDiveCoverageSummary["severity_breakdown"]> = {},
): DeepDiveCoverageSummary {
  return {
    coverage_band: "high",
    total_rules: 164,
    rules_executed: 142,
    rules_skipped_no_data: 22,
    rules_with_findings: 0,
    total_findings: 0,
    severity_breakdown: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      ...overrides,
    },
  };
}

describe("MobileViewportStripe", () => {
  it("renders nothing when coverage is undefined", () => {
    const { container } = render(<MobileViewportStripe coverage={undefined} />);
    expect(container.querySelector(".dd-mobile-stripe")).toBeNull();
  });

  it("renders nothing when severity_breakdown is missing", () => {
    const { container } = render(
      <MobileViewportStripe
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        coverage={{ coverage_band: null, total_rules: 0 } as any}
      />,
    );
    expect(container.querySelector(".dd-mobile-stripe")).toBeNull();
  });

  it("renders nothing when no findings are present", () => {
    const { container } = render(
      <MobileViewportStripe coverage={makeCoverage()} />,
    );
    expect(container.querySelector(".dd-mobile-stripe")).toBeNull();
  });

  it("picks 'critical' when present, regardless of other severities", () => {
    const { container } = render(
      <MobileViewportStripe
        coverage={makeCoverage({ critical: 1, high: 5, medium: 10, low: 3 })}
      />,
    );
    const stripe = container.querySelector(".dd-mobile-stripe");
    expect(stripe).not.toBeNull();
    expect(stripe!.getAttribute("data-sev")).toBe("critical");
  });

  it("picks 'high' when criticals are zero", () => {
    const { container } = render(
      <MobileViewportStripe
        coverage={makeCoverage({ high: 2, medium: 10, low: 3 })}
      />,
    );
    expect(
      container.querySelector(".dd-mobile-stripe")!.getAttribute("data-sev"),
    ).toBe("high");
  });

  it("picks 'low' when only low-severity findings", () => {
    const { container } = render(
      <MobileViewportStripe coverage={makeCoverage({ low: 1 })} />,
    );
    expect(
      container.querySelector(".dd-mobile-stripe")!.getAttribute("data-sev"),
    ).toBe("low");
  });

  it("picks 'informational' when only informational findings", () => {
    const { container } = render(
      <MobileViewportStripe coverage={makeCoverage({ informational: 1 })} />,
    );
    expect(
      container.querySelector(".dd-mobile-stripe")!.getAttribute("data-sev"),
    ).toBe("informational");
  });

  it("survives non-numeric severity values (Number coercion fallback)", () => {
    expect(() =>
      render(
        <MobileViewportStripe
          coverage={
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            {
              coverage_band: null,
              total_rules: 0,
              rules_executed: 0,
              rules_skipped_no_data: 0,
              rules_with_findings: 0,
              total_findings: 1,
              severity_breakdown: {
                critical: "1" as any,
                high: 0,
                medium: 0,
                low: 0,
                informational: 0,
              },
            } as any
          }
        />,
      ),
    ).not.toThrow();
  });
});
