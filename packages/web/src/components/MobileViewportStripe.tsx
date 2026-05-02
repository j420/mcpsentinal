"use client";
/**
 * MobileViewportStripe — 4-px coloured strip pinned to the viewport
 * top, mobile-only.
 *
 * The Verdict bar is sticky but tall; on a phone, once the user scrolls
 * past it, there's no always-visible "the page is critical / clean"
 * signal. This strip fills that gap: a single 4-px line of severity
 * colour pinned to the top of the viewport, derived from the worst
 * present severity in `coverage.severity_breakdown`.
 *
 * Hidden via CSS above 720px — desktop already has the verdict bar
 * sticky-pinned. On mobile, the strip is the at-a-glance status the
 * user can never miss.
 *
 * Severity priority: critical > high > medium > low > informational.
 * No findings → no strip rendered (honest gap; the user shouldn't be
 * told there's a problem when there isn't one).
 *
 * Pure presentational client component — props in, span out.
 */

import React from "react";
import type { DeepDiveCoverageSummary } from "@/lib/deep-dive";

interface MobileViewportStripeProps {
  coverage: DeepDiveCoverageSummary | undefined;
}

/** Severity-rank order for picking the worst-present band. */
const SEVERITY_PRIORITY: ReadonlyArray<
  keyof DeepDiveCoverageSummary["severity_breakdown"]
> = ["critical", "high", "medium", "low", "informational"];

export default function MobileViewportStripe({
  coverage,
}: MobileViewportStripeProps) {
  // Defensive: production data may have a partial / missing breakdown
  // (older api response). Render nothing in that case — the verdict
  // bar already carries the headline.
  const breakdown =
    coverage &&
    coverage.severity_breakdown &&
    typeof coverage.severity_breakdown === "object"
      ? coverage.severity_breakdown
      : null;
  if (!breakdown) return null;

  let worst: (typeof SEVERITY_PRIORITY)[number] | null = null;
  for (const sev of SEVERITY_PRIORITY) {
    if ((Number(breakdown[sev]) || 0) > 0) {
      worst = sev;
      break;
    }
  }
  if (!worst) return null; // no findings → no strip

  // sev-info is the css var name for "informational" severity.
  const tokenName = worst === "informational" ? "info" : worst;
  return (
    <div
      className="dd-mobile-stripe"
      data-sev={worst}
      style={{ background: `var(--sev-${tokenName})` }}
      role="presentation"
      aria-hidden="true"
    />
  );
}
