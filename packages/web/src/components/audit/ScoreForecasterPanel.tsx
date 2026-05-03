"use client";
/**
 * §X Score Forecaster — interactive "what if I fix these findings?" panel.
 *
 * The first interactive surface on the page. Crawls the deep-dive payload
 * for findings, lets the user toggle each as "would resolve", and recomputes
 * the projected score live. Drives developer behaviour toward high-leverage
 * fixes — a CISO sees "fix these 3 criticals → score 67 → 91" and knows
 * exactly where to invest.
 *
 * Score model: faithful reconstruction of the scorer's `100 − Σ(penalty)`
 * formula, with severity weights matching `agent_docs/scoring-algorithm.md`
 * and the lethal-trifecta cap at 40 if F1 or I13 remain unresolved. The
 * client-side computation is approximate — the canonical authority remains
 * the scorer — but it's accurate enough for the "where do I invest?"
 * decision the panel exists to drive. A small disclaimer makes the
 * approximation honest.
 *
 * Conservative bias: the panel never CLAIMS a fix will happen — only that
 * IF the listed findings were resolved, THEN the projected score. The
 * verbiage is precise, never aspirational.
 */

import React, { useMemo, useState } from "react";
import type { DeepDiveCategory, DeepDiveFinding, DeepDiveSeverity } from "@/lib/deep-dive";
import { scoreBand, bandLabel } from "@/lib/score-band";

// Severity weights — must match packages/scorer/src/scorer.ts SEVERITY_WEIGHTS.
// Centralised in one constant so a future change is mechanical (and a
// regression test in the scorer pins the canonical values).
const SEVERITY_WEIGHTS: Record<DeepDiveSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 1,
};

interface ForecastableFinding {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: DeepDiveSeverity;
  confidence: number;
  evidence: string;
  remediation: string;
  is_lethal_trifecta: boolean;
  /** weight × confidence — what subtracting this finding adds back to the score. */
  recovery: number;
}

/**
 * Crawl the deep-dive categories, dedupe by canonical placement, and
 * project to the forecaster's flat shape. Sorted by recovery desc so the
 * highest-leverage fixes are visible first.
 */
function collectFindings(categories: DeepDiveCategory[]): ForecastableFinding[] {
  const out: ForecastableFinding[] = [];
  const seen = new Set<string>();
  for (const cat of categories ?? []) {
    for (const sub of cat.sub_categories ?? []) {
      for (const rule of sub.rules ?? []) {
        // Honour the Phase 1.3 canonical-placement contract — cross-ref
        // appearances re-render the rule but don't contribute to the score.
        const canonical =
          (rule as { is_canonical?: boolean }).is_canonical !== false;
        if (!canonical) continue;
        for (const f of rule.findings ?? []) {
          if (seen.has(f.id)) continue;
          seen.add(f.id);
          const weight = SEVERITY_WEIGHTS[f.severity] ?? 0;
          const conf = Number.isFinite(f.confidence) ? f.confidence : 1.0;
          out.push({
            id: f.id,
            rule_id: rule.rule_id,
            rule_name: rule.name,
            severity: f.severity,
            confidence: conf,
            evidence: f.evidence,
            remediation: f.remediation || rule.remediation,
            is_lethal_trifecta: rule.rule_id === "F1" || rule.rule_id === "I13",
            recovery: Math.round(weight * conf * 100) / 100,
          });
        }
      }
    }
  }
  out.sort((a, b) => b.recovery - a.recovery);
  return out;
}

/** Apply the lethal-trifecta cap if any unresolved finding still triggers it. */
function applyTrifectaCap(score: number, unresolved: ForecastableFinding[]): number {
  if (unresolved.some((f) => f.is_lethal_trifecta) && score > 40) {
    return 40;
  }
  return score;
}

const SEVERITY_RANK: Record<DeepDiveSeverity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, informational: 1,
};

const SEVERITY_LABEL: Record<DeepDiveSeverity, string> = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", informational: "INFO",
};

const TOP_N = 8;

export default function ScoreForecasterPanel({
  currentScore,
  categories,
}: {
  /** Current persisted score (the verdict number). */
  currentScore: number;
  /** Full categories tree from the deep-dive payload. */
  categories: DeepDiveCategory[] | null | undefined;
}) {
  const safeCats = Array.isArray(categories) ? categories : [];
  const allFindings = useMemo(() => collectFindings(safeCats), [safeCats]);
  const top = allFindings.slice(0, TOP_N);

  const [resolved, setResolved] = useState<Set<string>>(() => new Set());

  // Empty-state: no findings to forecast on. The panel still renders so
  // the user knows the forecaster exists; an explicit empty state is
  // honest about why it has nothing to show.
  if (allFindings.length === 0) {
    return (
      <section
        className="audit-panel audit-panel-forecaster audit-panel-empty"
        aria-label="Score forecaster — no findings to model"
      >
        <header className="audit-section-head">
          <h3 className="audit-section-title">Score forecast</h3>
        </header>
        <p className="audit-panel-empty-text">
          No findings on file for this server — there is nothing to forecast.
          The score is as good as it can be with the current rule set.
        </p>
      </section>
    );
  }

  // Live recompute. We sum the recoveries of resolved findings and add
  // them back to the current score. Then re-apply the trifecta cap if
  // any unresolved trifecta finding remains.
  const unresolved = allFindings.filter((f) => !resolved.has(f.id));
  const recoveryTotal = allFindings
    .filter((f) => resolved.has(f.id))
    .reduce((sum, f) => sum + f.recovery, 0);
  const naiveProjected = Math.min(100, currentScore + recoveryTotal);
  const projected = Math.round(applyTrifectaCap(naiveProjected, unresolved));

  const projectedBand = scoreBand(projected);
  const currentBand = scoreBand(currentScore);
  const bandImproved = projected > currentScore;
  const trifectaStillTripped = unresolved.some((f) => f.is_lethal_trifecta);

  const toggle = (id: string) =>
    setResolved((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const reset = () => setResolved(new Set());

  return (
    <section
      className={`audit-panel audit-panel-forecaster audit-tone-${projectedBand}`}
      aria-label="Score forecaster — model the impact of fixing findings"
      data-audit-forecast-projected={projected}
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Score forecast</h3>
        <span className="audit-section-sublabel">
          interactive — toggle findings as &quot;would resolve&quot;
        </span>
      </header>

      <div className="audit-forecast-meter" role="group" aria-label="Score before vs after">
        <div className="audit-forecast-meter-cell">
          <span className="audit-forecast-meter-eyebrow">CURRENT</span>
          <span className={`audit-forecast-meter-num audit-tone-${currentBand}`}>
            {currentScore}
          </span>
          <span className="audit-forecast-meter-band">
            {bandLabel(currentBand)}
          </span>
        </div>
        <span className="audit-forecast-meter-arrow" aria-hidden="true">→</span>
        <div className="audit-forecast-meter-cell">
          <span className="audit-forecast-meter-eyebrow">PROJECTED</span>
          <span className={`audit-forecast-meter-num audit-tone-${projectedBand}`}>
            {projected}
          </span>
          <span className="audit-forecast-meter-band">
            {bandLabel(projectedBand)}
          </span>
        </div>
        <div className="audit-forecast-meter-delta">
          <span
            className={`audit-forecast-delta-num ${
              bandImproved ? "audit-forecast-delta-up" : "audit-forecast-delta-flat"
            }`}
          >
            {bandImproved ? "+" : ""}
            {projected - currentScore}
          </span>
          <span className="audit-forecast-meter-band">points</span>
        </div>
      </div>

      {trifectaStillTripped && projected === 40 && (
        <p className="audit-forecast-warning" role="note">
          ⚠ Lethal trifecta still tripped — score capped at 40 until F1 or
          I13 is resolved. Fix the trifecta to unlock the rest of the
          recoverable points.
        </p>
      )}

      <p className="audit-forecast-help">
        Toggle the top {top.length} findings by recoverable points. The
        forecast applies the same severity weights and lethal-trifecta cap
        the scorer uses, but is an approximation — re-scan after fixing to
        see the canonical score.
      </p>

      <ul className="audit-forecast-findings" role="list">
        {top.map((f) => {
          const checked = resolved.has(f.id);
          const sev = f.severity;
          return (
            <li
              key={f.id}
              className={`audit-forecast-finding ${checked ? "audit-forecast-finding-on" : ""}`}
            >
              <label className="audit-forecast-finding-row">
                <input
                  type="checkbox"
                  className="audit-forecast-finding-cb"
                  checked={checked}
                  onChange={() => toggle(f.id)}
                  aria-label={`Mark ${f.rule_id} as would-resolve`}
                />
                <span className={`audit-forecast-sev audit-forecast-sev-${SEVERITY_RANK[sev]}`}>
                  {SEVERITY_LABEL[sev]}
                </span>
                <span className="audit-forecast-rule-id">{f.rule_id}</span>
                <span className="audit-forecast-rule-name">{f.rule_name}</span>
                <span className="audit-forecast-recovery">
                  +{f.recovery.toFixed(1)} pts
                </span>
                {f.is_lethal_trifecta && (
                  <span
                    className="audit-chip audit-chip-critical audit-forecast-trifecta"
                    title="Resolving this lifts the lethal-trifecta cap"
                  >
                    TRIFECTA
                  </span>
                )}
              </label>
              {checked && f.remediation && (
                <p className="audit-forecast-remediation">{f.remediation}</p>
              )}
            </li>
          );
        })}
      </ul>

      {allFindings.length > TOP_N && (
        <p className="audit-forecast-more">
          {allFindings.length - TOP_N} more finding{allFindings.length - TOP_N === 1 ? "" : "s"}{" "}
          not shown — listed in the Forensic Detail below by recoverable
          points.
        </p>
      )}

      {resolved.size > 0 && (
        <button
          type="button"
          className="audit-forecast-reset"
          onClick={reset}
          aria-label="Reset all toggles"
        >
          Reset
        </button>
      )}
    </section>
  );
}
