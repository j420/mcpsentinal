"use client";
/**
 * §4 Risk Summary Panel — per-category SAFE / CAUTION / UNKNOWN status
 * grid. RISK is intentionally NOT a category-level pill — the verdict
 * pill owns RISK. Three pill scales at the same severity ladder would
 * dilute the top-line signal.
 */

import React from "react";
import type { AuditRiskSummary, AuditCategoryStatus } from "@/lib/deep-dive";

const STATUS_TONE: Record<AuditCategoryStatus, string> = {
  SAFE: "good",
  CAUTION: "moderate",
  UNKNOWN: "muted",
};

const STATUS_GLYPH: Record<AuditCategoryStatus, string> = {
  SAFE: "✓",
  CAUTION: "▲",
  UNKNOWN: "○",
};

export default function RiskSummaryPanel({
  summary,
}: {
  summary: AuditRiskSummary | null | undefined;
}) {
  if (!summary || !Array.isArray(summary.categories)) {
    return (
      <section
        className="audit-panel audit-panel-risk audit-panel-empty"
        aria-label="Risk summary — not on file"
      >
        <p className="audit-panel-empty-text">
          Per-category risk roll-up is unavailable for this scan.
        </p>
      </section>
    );
  }

  const cats = summary.categories;

  return (
    <section
      className="audit-panel audit-panel-risk"
      aria-label="Risk summary by category"
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Risk by category</h3>
        <span className="audit-section-sublabel">
          {cats.length} {cats.length === 1 ? "category" : "categories"}
        </span>
      </header>

      <ul className="audit-risk-grid" role="list">
        {cats.map((c) => {
          const tone = STATUS_TONE[c.status] ?? "muted";
          const glyph = STATUS_GLYPH[c.status] ?? "·";
          return (
            <li
              key={c.category_id}
              className={`audit-risk-cell audit-risk-${tone}`}
              data-trace={`category:${c.category_id}`}
            >
              <a
                className="audit-risk-link"
                href={`#cat-${c.category_id}`}
                aria-label={`${c.name}: ${c.status}`}
              >
                <span className="audit-risk-glyph" aria-hidden="true">{glyph}</span>
                <span className="audit-risk-name">{c.name}</span>
                <span className={`audit-chip audit-chip-${tone} audit-risk-chip`}>
                  {c.status}
                </span>
              </a>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
