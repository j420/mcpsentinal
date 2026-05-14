/**
 * SkippedRulesBlock — collapsed footer block listing rules that were not
 * tested because we lack the necessary inputs.
 *
 * Doubles as the "give us source code / a live endpoint / a dependency
 * manifest" CTA. Groups by the SET of missing_inputs so all rules waiting
 * on the same input land in one bucket with one call-to-action.
 *
 * Default-collapsed via native `<details>`. No client state.
 */

import React from "react";
import type { SkippedGroup } from "./view-model";

export interface SkippedRulesBlockProps {
  groups: SkippedGroup[];
}

function ctaCopy(missingInputs: SkippedGroup["missingInputs"]): string {
  if (missingInputs.length === 0) return "Provide more context to unlock these tests";
  const parts = missingInputs.map((m) => {
    switch (m) {
      case "source_code":
        return "publish your source on GitHub";
      case "connection":
        return "register a live MCP endpoint";
      case "dependencies":
        return "expose your package manifest";
    }
  });
  return `To unlock these tests: ${parts.join(" and ")}.`;
}

export default function SkippedRulesBlock({
  groups,
}: SkippedRulesBlockProps): React.ReactElement {
  const total = groups.reduce((n, g) => n + g.rules.length, 0);

  return (
    <details className="fv-skipped" id="skipped">
      <summary className="fv-skipped-sum">
        <span className="fv-skipped-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
            <circle cx="8" cy="8" r="6.5" stroke="currentColor" strokeWidth="1.5" />
            <path
              d="M5.5 8.5l2 2 3-4.5"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
        <span className="fv-skipped-label">
          Test <strong>{total}</strong> more rule{total === 1 ? "" : "s"} — give us
          more context
        </span>
        <span className="fv-skipped-meta">
          {groups.length} input gap{groups.length === 1 ? "" : "s"}
        </span>
      </summary>

      <div className="fv-skipped-body">
        {groups.map((g) => (
          <section key={g.key} className="fv-skipped-group">
            <header className="fv-skipped-group-head">
              <span className="fv-skipped-group-label">{g.label}</span>
              <span className="fv-skipped-group-count">
                {g.rules.length} rule{g.rules.length === 1 ? "" : "s"}
              </span>
            </header>
            <p className="fv-skipped-cta">{ctaCopy(g.missingInputs)}</p>
            <ul className="fv-skipped-rules">
              {g.rules.map((r) => (
                <li
                  key={`${r.categoryId}-${r.subCategoryId}-${r.rule.rule_id}`}
                  className="fv-skipped-rule"
                  data-severity={r.rule.severity}
                >
                  <span className="fv-skipped-rule-id">{r.rule.rule_id}</span>
                  <span className="fv-skipped-rule-name">{r.rule.name}</span>
                  <span className="fv-skipped-rule-cat">
                    {r.categoryTitle}
                    <span aria-hidden="true"> › </span>
                    {r.subCategoryTitle}
                  </span>
                </li>
              ))}
            </ul>
          </section>
        ))}
      </div>
    </details>
  );
}
