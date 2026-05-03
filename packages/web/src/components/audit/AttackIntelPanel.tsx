"use client";
/**
 * §3 Attack Intelligence Panel — top 3-5 kill chains with explicit
 * source → propagation → sink trio + per-chain outcome chip
 * (BLOCKED / NOT_OBSERVED / VULNERABLE).
 *
 * The audit-summary derivation already orders chains by exploitability
 * desc and caps at 5. This panel just renders.
 *
 * Outcome chip semantics:
 *   VULNERABLE   — chain rated critical/high; defenses absent or weak
 *   NOT_OBSERVED — chain shape exists but no exploitation evidence
 *   BLOCKED      — chain rated low; engine sees mitigations
 */

import React from "react";
import type { AuditAttackIntelligence, AuditAttackOutcome } from "@/lib/deep-dive";

const OUTCOME_TONE: Record<AuditAttackOutcome, string> = {
  VULNERABLE: "critical",
  NOT_OBSERVED: "moderate",
  BLOCKED: "good",
};

const OUTCOME_LABEL: Record<AuditAttackOutcome, string> = {
  VULNERABLE: "VULNERABLE",
  NOT_OBSERVED: "NOT OBSERVED",
  BLOCKED: "BLOCKED",
};

export default function AttackIntelPanel({
  intel,
}: {
  intel: AuditAttackIntelligence | null | undefined;
}) {
  const scenarios = intel && Array.isArray(intel.scenarios) ? intel.scenarios : [];

  if (scenarios.length === 0) {
    return (
      <section
        className="audit-panel audit-panel-attack audit-panel-empty"
        aria-label="Attack intelligence — no kill chains on file"
      >
        <header className="audit-section-head">
          <h3 className="audit-section-title">Attack intelligence</h3>
        </header>
        <p className="audit-panel-empty-text">
          No multi-step attack scenarios were synthesised for this server in the
          latest scan. This is the honest absence of cross-server exploitation
          evidence — not a guarantee no chain exists.
        </p>
      </section>
    );
  }

  return (
    <section
      className="audit-panel audit-panel-attack"
      aria-label={`Attack intelligence: ${scenarios.length} scenarios`}
    >
      <header className="audit-section-head">
        <h3 className="audit-section-title">Attack intelligence</h3>
        <span className="audit-section-sublabel">
          top {scenarios.length} kill chain{scenarios.length === 1 ? "" : "s"} by exploitability
        </span>
      </header>

      <ul className="audit-attack-list" role="list">
        {scenarios.map((s) => {
          const tone = OUTCOME_TONE[s.outcome] ?? "moderate";
          const label = OUTCOME_LABEL[s.outcome] ?? s.outcome;
          return (
            <li
              key={s.chain_id}
              className={`audit-attack-card audit-tone-${tone}`}
              data-trace={`kill-chain:${s.chain_id}`}
            >
              <header className="audit-attack-card-head">
                <span className="audit-attack-id">{s.chain_id}</span>
                <span className="audit-attack-name">{s.name}</span>
                <span
                  className={`audit-chip audit-chip-${tone}`}
                  aria-label={`Outcome: ${label}`}
                >
                  {label}
                </span>
              </header>

              <p className="audit-attack-narrative">{s.narrative}</p>

              <ol className="audit-attack-trio" aria-label="Source → propagation → sink">
                <li className="audit-attack-trio-item audit-attack-trio-source">
                  <span className="audit-attack-trio-eyebrow">Source</span>
                  <span className="audit-attack-trio-text">{s.source}</span>
                </li>
                {s.propagation.length > 0 &&
                  s.propagation.map((p, i) => (
                    <li
                      key={i}
                      className="audit-attack-trio-item audit-attack-trio-prop"
                    >
                      <span className="audit-attack-trio-eyebrow">Propagation</span>
                      <span className="audit-attack-trio-text">{p}</span>
                    </li>
                  ))}
                <li className="audit-attack-trio-item audit-attack-trio-sink">
                  <span className="audit-attack-trio-eyebrow">Sink</span>
                  <span className="audit-attack-trio-text">{s.sink}</span>
                </li>
              </ol>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
