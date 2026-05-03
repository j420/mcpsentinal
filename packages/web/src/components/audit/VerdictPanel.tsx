"use client";
/**
 * §1 Verdict Panel — the SAFE / CAUTION / RISK pill, score, 2-3 reasons,
 * and one-sentence "what could go wrong" scenario.
 *
 * Top-of-page band a CISO reads in 30 seconds. Conservative bias: when
 * the API derivation is unsure, this panel still renders an honest empty
 * state rather than guessing.
 */

import React from "react";
import type { AuditVerdict } from "@/lib/deep-dive";
import { bandLabel } from "@/lib/score-band";

const PILL_COPY: Record<AuditVerdict["pill"], { label: string; tone: string }> = {
  SAFE: { label: "SAFE", tone: "good" },
  CAUTION: { label: "CAUTION", tone: "moderate" },
  RISK: { label: "RISK", tone: "critical" },
};

export default function VerdictPanel({
  verdict,
}: {
  verdict: AuditVerdict | null | undefined;
}) {
  if (!verdict) {
    return (
      <section className="audit-panel audit-panel-verdict audit-panel-empty"
        aria-label="Verdict — not on file">
        <p className="audit-panel-empty-text">
          Verdict has not been derived for this server yet — the most likely cause
          is a stale cache entry from before the audit-summary deploy. Refresh in
          5 minutes.
        </p>
      </section>
    );
  }

  const pill = PILL_COPY[verdict.pill];
  const reasons = Array.isArray(verdict.reasons) ? verdict.reasons : [];

  return (
    <section
      className={`audit-panel audit-panel-verdict audit-tone-${pill.tone}`}
      aria-label={`Verdict: ${pill.label}, score ${verdict.score} of 100`}
      data-audit-pill={verdict.pill}
    >
      <header className="audit-verdict-head">
        <span
          className={`audit-pill audit-pill-verdict audit-pill-${pill.tone}`}
          aria-label={`Verdict pill: ${pill.label}`}
        >
          {pill.label}
        </span>
        <div className="audit-verdict-score">
          <span className="audit-verdict-score-num" aria-label={`Score ${verdict.score} of 100`}>
            {verdict.score}
          </span>
          <span className="audit-verdict-score-band">
            / 100 · {bandLabel(verdict.band)}
          </span>
        </div>
      </header>

      {reasons.length > 0 && (
        <ol className="audit-verdict-reasons" aria-label="Reasons for the verdict">
          {reasons.slice(0, 3).map((reason, i) => (
            <li key={i} className="audit-verdict-reason">
              {reason}
            </li>
          ))}
        </ol>
      )}

      <div className="audit-verdict-worst" aria-label="Worst-case scenario">
        <span className="audit-verdict-worst-label">What could go wrong</span>
        <p className="audit-verdict-worst-text">{verdict.worst_case}</p>
      </div>
    </section>
  );
}
