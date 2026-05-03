/**
 * score-band — single source of truth for the 0-100 score → band mapping.
 *
 * Phase 3.2 dedupe: previously this lived in BOTH
 *   `components/EvidenceSummaryHero.tsx:99`     (canonical)
 *   `components/DeepDiveHeroChrome.tsx:34`      (duplicate, with a regression-guard test)
 *
 * Two copies meant a future threshold change would silently drift one
 * surface vs the other. The Audit Verdict layer (Phase 2) made it three
 * — the API derivation also uses these thresholds. Centralising here.
 *
 * Thresholds match the public Score Interpretation table in
 * `agent_docs/scoring-algorithm.md`:
 *   80-100 → Good       (green)
 *   60-79  → Moderate   (yellow)
 *   40-59  → Poor       (orange)
 *   0-39   → Critical   (red)
 *
 * Do NOT change without updating that doc + the API's own
 * `packages/api/src/audit-summary.ts → scoreBand` (which intentionally
 * duplicates the thresholds because web cannot import from api).
 */

export type ScoreBand = "good" | "moderate" | "poor" | "critical";

export function scoreBand(score: number): ScoreBand {
  if (score >= 80) return "good";
  if (score >= 60) return "moderate";
  if (score >= 40) return "poor";
  return "critical";
}

export function bandLabel(band: ScoreBand): string {
  return { good: "Good", moderate: "Moderate", poor: "Poor", critical: "Critical" }[band];
}

/**
 * Discrete letter grade derived from the same thresholds (sub-divides the
 * "good" band so an 95 reads as A vs an 80 reads as A−). Kept here next
 * to scoreBand so a threshold change always touches both consistently.
 */
export function scoreToLetter(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "A−";
  if (score >= 70) return "B";
  if (score >= 60) return "C";
  if (score >= 50) return "D";
  if (score >= 40) return "D−";
  return "F";
}
