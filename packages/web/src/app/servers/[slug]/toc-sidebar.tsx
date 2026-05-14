/**
 * TocSidebar — sticky left-column navigation.
 *
 * Always-visible scaffold of the five-entity cascade. One row per
 * category with a severity dot + title + status count. Click any row to
 * scroll to that category section (via #category-<id> anchor). The
 * `<HashOpener/>` client island auto-expands the matching <details>
 * block when the hash changes so the reader lands inside the section.
 *
 * Hidden on mobile (<960px) — the sticky-header counts and the inline
 * category headers serve as navigation there.
 */

import React from "react";
import type { CascadeCategory } from "./view-model";

export interface TocSidebarProps {
  cascade: CascadeCategory[];
  counts: {
    findings: number;
    passed: number;
    skipped: number;
    total: number;
  };
}

function tocStatus(cat: CascadeCategory): {
  label: string;
  tone: "findings" | "skipped" | "clean";
} {
  if (cat.findingCount > 0) {
    return {
      label: `${cat.findingCount} finding${cat.findingCount === 1 ? "" : "s"}`,
      tone: "findings",
    };
  }
  if (cat.ruleCounts.skipped > 0 && cat.ruleCounts.findings === 0) {
    return {
      label: `${cat.ruleCounts.skipped} need${cat.ruleCounts.skipped === 1 ? "s" : ""} data`,
      tone: "skipped",
    };
  }
  return {
    label: `${cat.ruleCounts.passed}/${cat.ruleCounts.total} clean`,
    tone: "clean",
  };
}

export default function TocSidebar({
  cascade,
  counts,
}: TocSidebarProps): React.ReactElement {
  return (
    <aside className="fv-toc" aria-label="Audit cascade table of contents">
      <nav>
        <p className="fv-toc-eyebrow">The cascade</p>
        <ul className="fv-toc-list">
          {cascade.map((cat) => {
            const status = tocStatus(cat);
            return (
              <li
                key={cat.id}
                className="fv-toc-row"
                data-tone={status.tone}
                data-severity={cat.worstSeverity ?? "none"}
              >
                <a className="fv-toc-link" href={`#category-${cat.id}`}>
                  <span
                    className="fv-toc-dot"
                    data-severity={cat.worstSeverity ?? "none"}
                    aria-hidden="true"
                  />
                  <span className="fv-toc-title">{cat.title}</span>
                  <span className="fv-toc-meta">{status.label}</span>
                </a>
              </li>
            );
          })}
        </ul>
      </nav>

      <footer className="fv-toc-foot">
        <p className="fv-toc-foot-eyebrow">Scan totals</p>
        <ul className="fv-toc-totals">
          <li>
            <span>Findings</span>
            <strong className="fv-toc-total-findings">{counts.findings}</strong>
          </li>
          <li>
            <span>Skipped</span>
            <strong className="fv-toc-total-skipped">{counts.skipped}</strong>
          </li>
          <li>
            <span>Passed</span>
            <strong className="fv-toc-total-passed">{counts.passed}</strong>
          </li>
          <li>
            <span>Total rules</span>
            <strong>{counts.total}</strong>
          </li>
        </ul>
      </footer>
    </aside>
  );
}
