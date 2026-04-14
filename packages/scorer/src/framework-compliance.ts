/**
 * Framework Compliance Score (ADR-009)
 *
 * A SEPARATE sub-score from the existing `compliance_score` on `ScoreResult`,
 * which scores the deterministic K-category compliance-governance rules.
 *
 * This helper computes a per-framework compliance score for the
 * `@mcp-sentinel/compliance-agents` package's adversarial reports. It is
 * computed independently and is shown ONLY on compliance reports — it is
 * NOT folded into the deterministic `total_score` produced by `computeScore`.
 *
 * Algorithm: 100 minus the sum of severity penalties, floored at 0.
 * Severity weights are intentionally identical to the deterministic scorer's
 * `SEVERITY_WEIGHTS` so the two scores share an interpretive scale, but the
 * inputs are disjoint (compliance findings vs. deterministic findings).
 */

import type { Severity } from "@mcp-sentinel/database";

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 1,
};

export interface FrameworkComplianceFindingLike {
  severity: Severity;
}

/**
 * Compute the per-framework compliance score for a list of judge-confirmed
 * compliance findings. Returns an integer in [0, 100].
 *
 * The orchestrator in `@mcp-sentinel/compliance-agents` calls this once per
 * `ComplianceReport` (i.e. once per requested framework).
 */
export function computeFrameworkComplianceScore(
  findings: ReadonlyArray<FrameworkComplianceFindingLike>,
): number {
  let score = 100;
  for (const f of findings) {
    score -= SEVERITY_PENALTY[f.severity] ?? 1;
  }
  if (score < 0) return 0;
  if (score > 100) return 100;
  return Math.round(score);
}
