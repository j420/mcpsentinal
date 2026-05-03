"use client";
/**
 * §7 Confidence Panel — HIGH / MEDIUM / LOW confidence in the verdict
 * with explanatory factors. Distinct from the verdict pill (a SAFE
 * verdict at LOW confidence is materially different from SAFE at HIGH
 * — the page must surface both).
 */

import React from "react";
import type { AuditConfidence, AuditConfidenceLevel } from "@/lib/deep-dive";

const TONE: Record<AuditConfidenceLevel, string> = {
  HIGH: "good",
  MEDIUM: "moderate",
  LOW: "critical",
};

const HEADLINE: Record<AuditConfidenceLevel, string> = {
  HIGH: "All inputs available, every finding carries an evidence chain, low skip rate.",
  MEDIUM: "Adequate coverage, but some inputs missing or rules skipped.",
  LOW: "Verdict has limited coverage — re-scan with more inputs before relying on it.",
};

export default function ConfidencePanel({
  confidence,
}: {
  confidence: AuditConfidence | null | undefined;
}) {
  if (!confidence) {
    return (
      <section
        className="audit-panel audit-panel-confidence audit-panel-empty"
        aria-label="Confidence — not on file"
      >
        <p className="audit-panel-empty-text">
          Confidence band has not been derived for this scan.
        </p>
      </section>
    );
  }

  const tone = TONE[confidence.level] ?? "moderate";
  const factors = Array.isArray(confidence.factors) ? confidence.factors : [];

  return (
    <section
      className={`audit-panel audit-panel-confidence audit-tone-${tone}`}
      aria-label={`Verdict confidence: ${confidence.level}`}
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Verdict confidence</h3>
        <span className={`audit-chip audit-chip-${tone}`}>
          {confidence.level}
        </span>
      </header>
      <p className="audit-confidence-headline">{HEADLINE[confidence.level]}</p>
      {factors.length > 0 && (
        <ul className="audit-confidence-factors" aria-label="Factors driving the confidence band">
          {factors.map((f, i) => (
            <li key={i} className="audit-confidence-factor">
              <span className="audit-confidence-factor-glyph" aria-hidden="true">·</span>
              {f}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
