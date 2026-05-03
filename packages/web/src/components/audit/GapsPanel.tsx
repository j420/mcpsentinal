"use client";
/**
 * §5 Gaps Panel — what was NOT tested + why (missing inputs) + impact.
 *
 * Groups skipped rules by the SET of missing inputs so the page can render
 * "give us source code, we'll test these N rules" prompts. The data lands
 * here only after Phase 1.1 (analysis_coverage persisted) and Phase 1.2
 * (requires_inputs emitted by the methodology builder); pre-Phase-1 scans
 * report gaps: [].
 */

import React from "react";
import type { AuditGap, AuditImpact } from "@/lib/deep-dive";

const IMPACT_TONE: Record<AuditImpact, string> = {
  HIGH: "critical",
  MEDIUM: "moderate",
  LOW: "muted",
};

interface GapBucket {
  key: string;
  inputs: string[];
  gaps: AuditGap[];
  highestImpact: AuditImpact;
}

const IMPACT_RANK: Record<AuditImpact, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };

function bucketGaps(gaps: AuditGap[]): GapBucket[] {
  const buckets = new Map<string, GapBucket>();
  for (const g of gaps) {
    const inputs = [...g.missing_inputs].sort();
    const key = inputs.join("+") || "<no-input-tag>";
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { key, inputs, gaps: [], highestImpact: "LOW" };
      buckets.set(key, bucket);
    }
    bucket.gaps.push(g);
    if (IMPACT_RANK[g.impact] > IMPACT_RANK[bucket.highestImpact]) {
      bucket.highestImpact = g.impact;
    }
  }
  // Sort buckets by impact desc, then by gap count desc
  return Array.from(buckets.values()).sort((a, b) => {
    const impDiff = IMPACT_RANK[b.highestImpact] - IMPACT_RANK[a.highestImpact];
    if (impDiff !== 0) return impDiff;
    return b.gaps.length - a.gaps.length;
  });
}

const INPUT_PROSE: Record<string, string> = {
  source_code: "source code",
  connection: "live MCP connection",
  dependencies: "package manifest",
};

function bucketHeading(inputs: string[]): string {
  if (inputs.length === 0) return "no specific input";
  const labels = inputs.map((i) => INPUT_PROSE[i] ?? i);
  if (labels.length === 1) return `Need ${labels[0]}`;
  if (labels.length === 2) return `Need ${labels[0]} and ${labels[1]}`;
  return `Need ${labels.slice(0, -1).join(", ")}, and ${labels[labels.length - 1]}`;
}

export default function GapsPanel({
  gaps,
}: {
  gaps: AuditGap[] | null | undefined;
}) {
  const safe = Array.isArray(gaps) ? gaps : [];

  if (safe.length === 0) {
    return (
      <section
        className="audit-panel audit-panel-gaps audit-panel-empty"
        aria-label="Gaps — no rules skipped"
      >
        <header className="audit-section-head">
          <h3 className="audit-section-title">Gaps</h3>
        </header>
        <p className="audit-panel-empty-text">
          Every applicable rule had its required inputs available. No coverage
          gaps to report on this scan.
        </p>
      </section>
    );
  }

  const buckets = bucketGaps(safe);

  return (
    <section
      className="audit-panel audit-panel-gaps"
      aria-label={`${safe.length} skipped rule${safe.length === 1 ? "" : "s"} grouped by missing input`}
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Gaps</h3>
        <span className="audit-section-sublabel">
          {safe.length} rule{safe.length === 1 ? "" : "s"} skipped for missing inputs
        </span>
      </header>

      <ul className="audit-gaps-list" role="list">
        {buckets.map((b) => {
          const tone = IMPACT_TONE[b.highestImpact] ?? "muted";
          return (
            <li key={b.key} className={`audit-gap-bucket audit-tone-${tone}`}>
              <details className="audit-gap-details">
                <summary className="audit-gap-summary">
                  <span className="audit-gap-bucket-title">
                    {bucketHeading(b.inputs)}
                  </span>
                  <span className="audit-gap-bucket-count">
                    {b.gaps.length} rule{b.gaps.length === 1 ? "" : "s"}
                  </span>
                  <span className={`audit-chip audit-chip-${tone}`}>
                    {b.highestImpact} impact
                  </span>
                </summary>
                <ul className="audit-gap-rules" role="list">
                  {b.gaps.map((g) => (
                    <li key={g.rule_id} className="audit-gap-rule">
                      <span className="audit-gap-rule-id">{g.rule_id}</span>
                      <span className="audit-gap-rule-name">{g.name}</span>
                      <span
                        className={`audit-chip audit-chip-${IMPACT_TONE[g.impact]} audit-gap-rule-impact`}
                      >
                        {g.impact}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
