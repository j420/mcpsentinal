"use client";
/**
 * §6 Recommendation Panel — YES / CONDITIONAL / NO with rationale +
 * conditions + disclaimer.
 *
 * Distinct visual shape from the verdict pill (button-style block, not
 * a chip) — three pill scales on the same page risks dilution; using
 * different shapes per scale keeps each signal readable.
 *
 * The rationale is the audit trail. Every YES/CONDITIONAL/NO must show
 * WHY — auditable means "you can read which decision-tree rules fired".
 */

import React from "react";
import type { AuditRecommendation, AuditRecommendationDecision } from "@/lib/deep-dive";

const DECISION_COPY: Record<AuditRecommendationDecision, {
  label: string;
  tone: string;
  headline: string;
}> = {
  YES: {
    label: "YES",
    tone: "good",
    headline: "Suitable for production with the controls measured here.",
  },
  CONDITIONAL: {
    label: "CONDITIONAL",
    tone: "moderate",
    headline: "Production-eligible only after the conditions below are met.",
  },
  NO: {
    label: "NO",
    tone: "critical",
    headline: "Do not deploy to production at the current scan boundary.",
  },
};

export default function RecommendationPanel({
  recommendation,
}: {
  recommendation: AuditRecommendation | null | undefined;
}) {
  if (!recommendation) {
    return (
      <section
        className="audit-panel audit-panel-recommendation audit-panel-empty"
        aria-label="Recommendation — not on file"
      >
        <p className="audit-panel-empty-text">
          Recommendation engine has not produced a decision for this server yet.
          A re-scan with the current rules version will populate it.
        </p>
      </section>
    );
  }

  const decision = DECISION_COPY[recommendation.use_in_production];
  const rationale = Array.isArray(recommendation.rationale) ? recommendation.rationale : [];
  const conditions = Array.isArray(recommendation.conditions) ? recommendation.conditions : [];

  return (
    <section
      className={`audit-panel audit-panel-recommendation audit-tone-${decision.tone}`}
      aria-label={`Production recommendation: ${decision.label}`}
      data-audit-recommendation={recommendation.use_in_production}
    >
      <header className="audit-rec-head">
        <span className="audit-rec-eyebrow">PRODUCTION RECOMMENDATION</span>
        <div className={`audit-rec-block audit-rec-${decision.tone}`}>
          <span className="audit-rec-label">{decision.label}</span>
          <span className="audit-rec-headline">{decision.headline}</span>
        </div>
      </header>

      {conditions.length > 0 && (
        <div className="audit-rec-conditions" aria-label="Conditions that must be satisfied">
          <h4 className="audit-rec-section-title">Conditions</h4>
          <ul className="audit-rec-conditions-list">
            {conditions.map((c, i) => (
              <li key={i} className="audit-rec-condition">
                <span className="audit-rec-bullet" aria-hidden="true">→</span>
                {c}
              </li>
            ))}
          </ul>
        </div>
      )}

      {rationale.length > 0 && (
        <div className="audit-rec-rationale" aria-label="Decision rationale">
          <h4 className="audit-rec-section-title">Decision rationale</h4>
          <ol className="audit-rec-rationale-list">
            {rationale.map((r, i) => (
              <li key={i} className="audit-rec-rationale-item">{r}</li>
            ))}
          </ol>
        </div>
      )}

      {recommendation.disclaimer && (
        <p className="audit-rec-disclaimer" role="note">
          {recommendation.disclaimer}
        </p>
      )}
    </section>
  );
}
