/**
 * GradeBreakdownTab — explains how the score was computed.
 *
 * Pivots from a 7-weighted-categories model to the 5 sub-scores actually
 * stored in the database (code/deps/config/description/behavior). Every
 * deduction is a real finding with a canonical severity weight from
 * agent_docs/scoring-algorithm.md (critical −25, high −15, medium −8,
 * low −3, informational −1). No invented categories.
 *
 * Server component — no state, no LLM, deterministic per ADR-006.
 */

import React from "react";
import { RULE_NAMES } from "@/components/cdd-data";
import { scoreBand, scoreToLetter } from "@/components/EvidenceSummaryHero";

interface Finding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
}

interface ScoreDetail {
  total_score: number;
  code_score: number;
  deps_score: number;
  config_score: number;
  description_score: number;
  behavior_score: number;
}

interface Props {
  score_detail: ScoreDetail | null;
  findings: Finding[];
}

const SEVERITY_WEIGHT: Record<Finding["severity"], number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 1,
};

interface SubScoreSpec {
  key: keyof Pick<ScoreDetail, "code_score" | "deps_score" | "config_score" | "description_score" | "behavior_score">;
  label: string;
  prefixes: string[]; // first-letter rule_id prefixes routed to this sub-score
}

// CATEGORY_MAP equivalent (web-side mirror) — see packages/scorer/src/scorer.ts.
const SUB_SCORES: SubScoreSpec[] = [
  { key: "code_score",        label: "Code Analysis",            prefixes: ["C"] },
  { key: "deps_score",        label: "Dependencies",             prefixes: ["D"] },
  { key: "description_score", label: "Description Analysis",     prefixes: ["A"] },
  { key: "behavior_score",    label: "Behavior",                 prefixes: ["E"] },
  {
    key: "config_score",
    label: "Configuration & Ecosystem",
    prefixes: ["B", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q"],
  },
];

function categoryFor(ruleId: string): SubScoreSpec | null {
  const letter = ruleId.charAt(0).toUpperCase();
  return SUB_SCORES.find((s) => s.prefixes.includes(letter)) ?? null;
}

function severityRank(s: Finding["severity"]): number {
  return { critical: 0, high: 1, medium: 2, low: 3, informational: 4 }[s];
}

export default function GradeBreakdownTab({ score_detail, findings }: Props) {
  if (!score_detail) {
    return (
      <section className="gbt-empty">
        <p className="gbt-empty-msg">Score detail not yet available for this server.</p>
      </section>
    );
  }

  // Bucket findings into sub-scores
  const bucketed = new Map<string, Finding[]>();
  for (const f of findings) {
    const cat = categoryFor(f.rule_id);
    if (!cat) continue;
    const arr = bucketed.get(cat.key) ?? [];
    arr.push(f);
    bucketed.set(cat.key, arr);
  }

  // Stable severity-then-rule-id sort within each bucket
  for (const arr of bucketed.values()) {
    arr.sort((a, b) =>
      severityRank(a.severity) - severityRank(b.severity)
        || a.rule_id.localeCompare(b.rule_id),
    );
  }

  const lethal = findings.some((f) => f.rule_id === "F1" || f.rule_id === "I13");
  const totalRaw = score_detail.total_score;
  const totalEffective = lethal ? Math.min(totalRaw, 40) : totalRaw;
  const totalBand = scoreBand(totalEffective);

  return (
    <section id="grade-breakdown" className="gbt-section">
      <p className="gbt-intro">
        The total score starts at <strong>100</strong> and is reduced by a fixed
        per-finding penalty: critical −25, high −15, medium −8, low −3, informational −1.
        Findings are bucketed into the five sub-scores below — each sub-score is the
        same algorithm applied to the rules it owns.
      </p>

      <div className="gbt-list">
        {SUB_SCORES.map((spec) => {
          const subScore = score_detail[spec.key];
          const band = scoreBand(subScore);
          const ded = bucketed.get(spec.key) ?? [];
          return (
            <div key={spec.key} className="gbt-row">
              <div className="gbt-row-head">
                <span className="gbt-cat-label">{spec.label}</span>
                <span
                  className="gbt-cat-score"
                  style={{ color: `var(--${band})` }}
                >
                  {subScore}/100
                </span>
              </div>
              <div className="gbt-bar-track" aria-hidden="true">
                <div
                  className="gbt-bar-fill"
                  style={{
                    width: `${Math.max(0, Math.min(100, subScore))}%`,
                    background: `var(--${band})`,
                  }}
                />
              </div>
              {ded.length === 0 ? (
                <p className="gbt-no-ded">no deductions</p>
              ) : (
                <ul className="gbt-ded-list">
                  {ded.map((f) => (
                    <li key={f.id} className="gbt-ded-row">
                      <span
                        className={`gbt-ded-sev sev-badge sev-${f.severity}`}
                      >
                        {f.severity}
                      </span>
                      <span className="gbt-ded-rule">{f.rule_id}</span>
                      <span className="gbt-ded-name">
                        {RULE_NAMES[f.rule_id] ?? f.rule_id}
                      </span>
                      <span className="gbt-ded-pts">
                        −{SEVERITY_WEIGHT[f.severity]}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
      </div>

      <div className="gbt-total">
        <div className="gbt-total-num" style={{ color: `var(--${totalBand})` }}>
          {totalEffective}
        </div>
        <div className="gbt-total-of">/ 100</div>
        <div
          className="gbt-total-letter"
          style={{ color: `var(--${totalBand})` }}
          title="Synthesized from total_score (UI label only)"
        >
          {scoreToLetter(totalEffective)}
        </div>
      </div>

      {lethal && (
        <p className="gbt-cap-note">
          F1 (Lethal Trifecta) or I13 (Cross-Config Trifecta) detected — the total is
          capped at 40 regardless of the per-category sum, per the scoring algorithm.
        </p>
      )}
    </section>
  );
}
