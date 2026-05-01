/**
 * SubCategorySection
 * ──────────────────
 * Renders one sub-category of the deep-dive long-scroll.
 *
 * Anatomy:
 *   • Anchor: `id={`sub-${sub.id}`}` (with `scroll-margin-top: 96px` so
 *     deep-link jumps clear the chrome strip Agent 3 mounts above).
 *   • Header: title (h3), summary copy, and a counts line
 *     ("3 of 3 rules tested · 1 finding") — reads like the validation
 *     receipts in DetectionQualityFooter so the visual language stays
 *     consistent across the dossier.
 *   • Body: a vertical stack of `<RuleEvidenceCard/>` for every rule.
 *     Cross-referenced rules render via the same component with
 *     `crossRef={true}`, which collapses to a one-line "see canonical"
 *     deep-link instead of repeating the full card.
 *
 * Server component — no hooks, no client JS. Children handle their own
 * collapse via native `<details>`.
 *
 * Props:
 *   • `sub` — DeepDiveSubCategory from `lib/deep-dive.ts` (frozen contract).
 *   • `crossReferencedRuleIds` — set of rule_ids whose canonical home is
 *     a different sub-category. When provided, those rules render in
 *     cross-ref mode here. When omitted, every rule renders canonically.
 */

import React from "react";
import RuleEvidenceCard from "@/components/RuleEvidenceCard";
import type {
  DeepDiveSubCategory,
  DeepDiveCounts,
} from "@/lib/deep-dive";

export interface SubCategorySectionProps {
  sub: DeepDiveSubCategory;
  /**
   * Optional set of rule_ids that should render in cross-ref form rather
   * than canonically. The page's main column resolves canonical placement
   * by inspecting `rule.cross_referenced_in[]`; everything else is
   * non-canonical and gets a `↗ see canonical` link.
   */
  crossReferencedRuleIds?: ReadonlySet<string>;
}

/**
 * Format the counts line. Reads as plain English so a reviewer doesn't
 * have to decode glyphs:
 *   "3 of 3 rules tested · 1 finding"
 *   "5 of 5 rules tested · all clean"
 *   "2 of 3 rules tested · 1 skipped (no source code)"
 */
function formatCountsLine(counts: DeepDiveCounts): string {
  const tested = counts.rules_total - counts.rules_skipped;
  const totalLabel = `${tested} of ${counts.rules_total} rule${
    counts.rules_total === 1 ? "" : "s"
  } tested`;

  const findings = counts.finding_count;
  let evidenceLabel: string;
  if (findings > 0) {
    evidenceLabel = `${findings} finding${findings === 1 ? "" : "s"}`;
  } else if (counts.rules_skipped > 0 && tested === 0) {
    evidenceLabel = `${counts.rules_skipped} skipped`;
  } else {
    evidenceLabel = "all clean";
  }

  // Mention skipped only when there's at least one skip AND we already
  // chose a different evidence label, otherwise the line gets noisy.
  const skippedNote =
    counts.rules_skipped > 0 && evidenceLabel !== `${counts.rules_skipped} skipped`
      ? ` · ${counts.rules_skipped} skipped`
      : "";

  return `${totalLabel} · ${evidenceLabel}${skippedNote}`;
}

export default function SubCategorySection({
  sub,
  crossReferencedRuleIds,
}: SubCategorySectionProps) {
  const countsLine = formatCountsLine(sub.counts);
  const xrefSet = crossReferencedRuleIds ?? new Set<string>();

  return (
    <section
      id={`sub-${sub.id}`}
      className="scs-section"
      aria-labelledby={`scs-title-${sub.id}`}
      data-scs-id={sub.id}
    >
      <header className="scs-head">
        <h3 id={`scs-title-${sub.id}`} className="scs-title">
          {sub.title}
        </h3>
        {sub.summary && <p className="scs-summary">{sub.summary}</p>}
        <p className="scs-counts" aria-label={`Sub-category counts: ${countsLine}`}>
          {countsLine}
        </p>
      </header>

      <div className="scs-rules">
        {sub.rules.map((rule) => (
          <RuleEvidenceCard
            key={rule.rule_id}
            rule={rule}
            crossRef={xrefSet.has(rule.rule_id)}
          />
        ))}
      </div>
    </section>
  );
}
