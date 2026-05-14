/**
 * SubCategoryRail — the "sub-category" entity made visible.
 *
 * Quieter than CategoryRail but still a labeled unit. Renders:
 *   - Eyebrow label "SUB-CATEGORY"
 *   - Title (h3)
 *   - Inline severity histogram (smaller than category)
 *   - Optional one-line summary
 *   - Finding + rule counts
 *
 * Indented relative to the category rail.
 */

import React from "react";
import type { DeepDiveSeverity } from "@/lib/deep-dive";
import type { SeverityHistogram } from "./view-model";

export interface SubCategoryRailProps {
  id: string;
  title: string;
  summary?: string;
  worstSeverity: DeepDiveSeverity;
  findingCount: number;
  ruleCount: number;
  severity: SeverityHistogram;
}

const SEVERITY_ORDER: DeepDiveSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

function subCategoryAnchor(id: string): string {
  return `sub-${id}`;
}

export default function SubCategoryRail({
  id,
  title,
  summary,
  worstSeverity,
  findingCount,
  ruleCount,
  severity,
}: SubCategoryRailProps): React.ReactElement {
  const buckets = SEVERITY_ORDER.filter((s) => severity[s] > 0);

  return (
    <header
      className="fv-sub-rail"
      id={subCategoryAnchor(id)}
      data-severity={worstSeverity}
    >
      <div className="fv-sub-rail-row1">
        <span className="fv-sub-eyebrow">Sub-category</span>
        <h3 className="fv-sub-title">{title}</h3>
        {buckets.length > 0 && (
          <span
            className="fv-sub-pips"
            role="img"
            aria-label={`Severity: ${buckets
              .map((s) => `${severity[s]} ${s}`)
              .join(", ")}`}
          >
            {buckets.map((s) => (
              <span
                key={s}
                className="fv-sub-pip"
                data-severity={s}
                title={`${severity[s]} ${s}`}
              >
                {severity[s]}
              </span>
            ))}
          </span>
        )}
        <span className="fv-sub-count">
          <strong>{ruleCount}</strong> rule{ruleCount === 1 ? "" : "s"}
          <span aria-hidden="true"> · </span>
          <strong>{findingCount}</strong> finding{findingCount === 1 ? "" : "s"}
        </span>
      </div>
      {summary && <p className="fv-sub-summary">{summary}</p>}
    </header>
  );
}
