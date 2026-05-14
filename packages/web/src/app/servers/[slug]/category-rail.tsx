/**
 * CategoryRail — the "category" entity made visible.
 *
 * Not a card, but no longer just a hairline either. Renders:
 *   - Eyebrow label "CATEGORY"
 *   - Title (h2, large)
 *   - Inline severity histogram strip (one bar per non-zero severity)
 *   - Framework cross-walk chips (OWASP, MITRE etc. from taxonomy YAML)
 *   - One-line summary
 *   - Rule count + finding count
 *   - Bottom hairline rule
 *
 * Severity histogram is rendered as a row of mini-bars, sized
 * proportionally to the share of findings in each severity bucket.
 * Tabular-numeric counts to the right.
 */

import React from "react";
import type { DeepDiveSeverity } from "@/lib/deep-dive";
import type { SeverityHistogram } from "./view-model";

export interface CategoryRailProps {
  id: string;
  title: string;
  summary?: string;
  worstSeverity: DeepDiveSeverity;
  findingCount: number;
  ruleCount: number;
  severity: SeverityHistogram;
  frameworks?: string[];
}

const SEVERITY_ORDER: DeepDiveSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

function categoryAnchor(id: string): string {
  return `category-${id}`;
}

function pct(value: number, total: number): number {
  if (total <= 0) return 0;
  return Math.max(2, Math.round((value / total) * 100));
}

export default function CategoryRail({
  id,
  title,
  summary,
  worstSeverity,
  findingCount,
  ruleCount,
  severity,
  frameworks = [],
}: CategoryRailProps): React.ReactElement {
  const total = findingCount;
  const buckets = SEVERITY_ORDER.filter((s) => severity[s] > 0);

  return (
    <div className="fv-cat-rail" data-severity={worstSeverity}>
      <div className="fv-cat-rail-row1">
        <span className="fv-cat-eyebrow">Category</span>
        <span
          className="fv-cat-dot"
          data-severity={worstSeverity}
          aria-hidden="true"
        />
        <h2 className="fv-cat-title" id={categoryAnchor(id)}>
          {title}
        </h2>
        {frameworks.length > 0 && (
          <span className="fv-cat-frameworks" aria-label="Compliance frameworks">
            {frameworks.map((f) => (
              <span key={f} className="fv-cat-fw">
                {f}
              </span>
            ))}
          </span>
        )}
      </div>

      {summary && <p className="fv-cat-summary">{summary}</p>}

      <div className="fv-cat-rail-row2">
        {buckets.length > 0 ? (
          <span
            className="fv-cat-histogram"
            role="img"
            aria-label={`Severity breakdown: ${buckets
              .map((s) => `${severity[s]} ${s}`)
              .join(", ")}`}
          >
            {buckets.map((s) => (
              <span
                key={s}
                className="fv-cat-histo-bar"
                data-severity={s}
                style={{ flex: pct(severity[s], total) }}
              >
                <span className="fv-cat-histo-count">{severity[s]}</span>
                <span className="fv-cat-histo-label">{s}</span>
              </span>
            ))}
          </span>
        ) : (
          <span className="fv-cat-histogram fv-cat-histogram-empty" />
        )}
        <span className="fv-cat-count" aria-hidden="true">
          <strong>{findingCount}</strong> finding{findingCount === 1 ? "" : "s"}
          <span aria-hidden="true"> · </span>
          <strong>{ruleCount}</strong> rule{ruleCount === 1 ? "" : "s"}
        </span>
      </div>
    </div>
  );
}
