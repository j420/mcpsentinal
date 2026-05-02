"use client";
/**
 * CategorySection
 * ───────────────
 * One top-level category of the deep-dive long-scroll.
 *
 * Marked `"use client"` so the page-level <SectionBoundary/> (a class-
 * based React error boundary, which by definition is client-side) can
 * actually catch a render exception in this subtree. Server-component
 * SSR throws bypass all client error boundaries and propagate to the
 * route-level error.tsx — i.e. HTTP 500. Pure render component (props
 * in, JSX out), so the directive is a no-op for functionality.
 *

 * Anatomy:
 *   • Anchor: `id={`cat-${cat.id}`}` (with `scroll-margin-top: 96px` so
 *     deep-link jumps clear the chrome strip Agent 3 mounts above).
 *   • Header: title (h2), summary, framework chips (the small badges
 *     that tell a CISO which compliance regime this category folds
 *     into), aggregate counts, and a proportional severity-breakdown
 *     bar coloured by the `--sev-${severity}` token namespace.
 *   • Body: a vertical stack of `<SubCategorySection/>` (which in turn
 *     stacks `<RuleEvidenceCard/>`s).
 *
 * Cross-reference handling: a rule's canonical home is the FIRST
 * sub-category it appears in. Subsequent appearances render in
 * cross-ref form (one-line "see canonical" deep-link). The set of
 * cross-referenced rule_ids per sub-category is computed once here so
 * the children stay simple and the canonical/non-canonical decision is
 * deterministic across renders.
 *
 * Server component — no hooks. The expand state lives in native
 * `<details>` inside the rule cards.
 */

import React from "react";
import SubCategorySection from "@/components/SubCategorySection";
import type {
  DeepDiveCategory,
  DeepDiveSeverityBreakdown,
} from "@/lib/deep-dive";

export interface CategorySectionProps {
  cat: DeepDiveCategory;
}

/* ─── Severity-bar helpers ─────────────────────────────────────────── */

const SEVERITY_ORDER: Array<keyof DeepDiveSeverityBreakdown> = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

const SEVERITY_LABELS: Record<keyof DeepDiveSeverityBreakdown, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  informational: "informational",
};

/** Total count across all severities — guards against zero division. */
function severityTotal(s: DeepDiveSeverityBreakdown): number {
  return s.critical + s.high + s.medium + s.low + s.informational;
}

function buildSeverityAriaLabel(s: DeepDiveSeverityBreakdown): string {
  const total = severityTotal(s);
  if (total === 0) {
    return "Severity breakdown: no findings in this category";
  }
  const parts: string[] = [];
  for (const k of SEVERITY_ORDER) {
    if (s[k] > 0) parts.push(`${s[k]} ${SEVERITY_LABELS[k]}`);
  }
  return `Severity breakdown: ${parts.join(", ")}`;
}

/**
 * Format the aggregate counts line. Reads as plain English so a CISO
 * gets the posture in one glance:
 *   "12 of 16 rules tested · 3 findings (1 critical, 2 high)"
 *   "9 of 9 rules tested · all clean"
 *   "0 of 7 rules tested · 7 skipped"
 */
function formatAggregateLine(cat: DeepDiveCategory): string {
  const c = cat.counts;
  const tested = c.rules_total - c.rules_skipped;

  let evidenceLabel: string;
  if (c.finding_count > 0) {
    evidenceLabel = `${c.finding_count} finding${c.finding_count === 1 ? "" : "s"}`;
  } else if (c.rules_skipped === c.rules_total && c.rules_total > 0) {
    evidenceLabel = `${c.rules_skipped} skipped`;
  } else {
    evidenceLabel = "all clean";
  }

  const skippedNote =
    c.rules_skipped > 0 && evidenceLabel !== `${c.rules_skipped} skipped`
      ? ` · ${c.rules_skipped} skipped`
      : "";

  return `${tested} of ${c.rules_total} rule${
    c.rules_total === 1 ? "" : "s"
  } tested · ${evidenceLabel}${skippedNote}`;
}

/* ─── Cross-reference resolver ────────────────────────────────────── */

/**
 * Build a map of sub-category-anchor → set of rule_ids that should render
 * in cross-ref form there.
 *
 * Cluster D reviewer M1 lesson: the API's `rule.cross_referenced_in[]` is
 * the authoritative cross-reference truth (computed from the taxonomy
 * YAML). For any rule we encounter inside a sub-category, if that rule
 * declares `cross_referenced_in` AND the current sub-category appears in
 * that list, this is a SECONDARY placement and renders as a "see
 * canonical" link. Otherwise it renders fully (canonical placement).
 *
 * Falls back to first-seen-wins ordering when the API hasn't populated
 * `cross_referenced_in` (older API responses or rules with no
 * cross-references). This preserves the prior behaviour as a safety net
 * without ignoring API truth when it's present.
 */
function buildCrossRefMap(
  cat: DeepDiveCategory,
): Map<string, Set<string>> {
  const seenCanonical = new Set<string>();
  const out = new Map<string, Set<string>>();

  for (const sub of cat.sub_categories) {
    const xrefHere = new Set<string>();
    for (const rule of sub.rules) {
      const xrefList = rule.cross_referenced_in;
      const isApiSecondary = Array.isArray(xrefList) && xrefList.some(
        (x) => x.category_id === cat.id && x.sub_category_id === sub.id,
      );
      if (isApiSecondary) {
        // API authoritative: this sub-category is a non-canonical placement.
        xrefHere.add(rule.rule_id);
        continue;
      }
      if (seenCanonical.has(rule.rule_id)) {
        // Fallback: API didn't tell us this is a secondary placement,
        // but we've already seen the rule canonically earlier in DOM
        // order. Keep prior behaviour.
        xrefHere.add(rule.rule_id);
      } else {
        seenCanonical.add(rule.rule_id);
      }
    }
    out.set(sub.id, xrefHere);
  }
  return out;
}

/* ─── Sub-components ───────────────────────────────────────────────── */

function SeverityBar({
  breakdown,
}: {
  breakdown: DeepDiveSeverityBreakdown;
}) {
  const total = severityTotal(breakdown);
  if (total === 0) {
    // Honest empty state: render the track with a "no findings" pip
    // rather than a zero-width invisible element. Ratio of receipt-style
    // visual language: never silently absent.
    return (
      <div
        className="cs-sev-bar cs-sev-bar-empty"
        role="img"
        aria-label="Severity breakdown: no findings in this category"
      >
        <span className="cs-sev-bar-empty-text">no findings</span>
      </div>
    );
  }
  return (
    <div
      className="cs-sev-bar"
      role="img"
      aria-label={buildSeverityAriaLabel(breakdown)}
    >
      {SEVERITY_ORDER.map((k) => {
        const count = breakdown[k];
        if (count <= 0) return null;
        const pct = (count / total) * 100;
        return (
          <span
            key={k}
            className={`cs-sev-bar-seg cs-sev-bar-seg-${k}`}
            style={{ width: `${pct}%` }}
            title={`${count} ${SEVERITY_LABELS[k]}`}
            aria-label={`${count} ${SEVERITY_LABELS[k]}`}
          />
        );
      })}
    </div>
  );
}

function FrameworkChips({ frameworks }: { frameworks: string[] }) {
  if (frameworks.length === 0) return null;
  return (
    <ul
      className="cs-fw-chips"
      aria-label="Frameworks this category contributes evidence toward"
    >
      {frameworks.map((fw, i) => (
        <li key={`${fw}-${i}`} className="cs-fw-chip" title={fw}>
          {fw}
        </li>
      ))}
    </ul>
  );
}

/* ─── Main component ───────────────────────────────────────────────── */

export default function CategorySection({ cat }: CategorySectionProps) {
  const crossRefMap = buildCrossRefMap(cat);
  const aggregateLine = formatAggregateLine(cat);
  const sevAria = buildSeverityAriaLabel(cat.counts.severity_breakdown);

  return (
    <section
      id={`cat-${cat.id}`}
      className="cs-section"
      aria-labelledby={`cs-title-${cat.id}`}
      data-cs-id={cat.id}
    >
      <header className="cs-head">
        <div className="cs-head-row">
          <h2 id={`cs-title-${cat.id}`} className="cs-title">
            {cat.title}
          </h2>
          <span
            className="cs-rule-count"
            aria-label={`${cat.counts.rules_total} rule${
              cat.counts.rules_total === 1 ? "" : "s"
            } in this category`}
          >
            {cat.counts.rules_total}
          </span>
        </div>

        {cat.summary && <p className="cs-summary">{cat.summary}</p>}

        <FrameworkChips frameworks={cat.frameworks} />

        <div className="cs-aggregate" aria-label={`Aggregate: ${aggregateLine}`}>
          <span className="cs-aggregate-text">{aggregateLine}</span>
        </div>

        <div className="cs-sev-wrap" aria-label={sevAria}>
          <SeverityBar breakdown={cat.counts.severity_breakdown} />
        </div>
      </header>

      <div className="cs-subs">
        {cat.sub_categories.map((sub) => (
          <SubCategorySection
            key={sub.id}
            sub={sub}
            crossReferencedRuleIds={crossRefMap.get(sub.id)}
          />
        ))}
      </div>
    </section>
  );
}
