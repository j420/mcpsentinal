/**
 * Evidence Chain Migration Tracker
 *
 * Tracks which rules have been migrated to produce structured EvidenceChains
 * instead of flat `evidence: string` findings.
 *
 * A fully migrated rule answers all 5 questions:
 *   1. WHERE — location of the vulnerability (file:line or tool:param)
 *   2. WHAT — verbatim text/pattern observed
 *   3. WHY — CVE or published research backing the finding
 *   4. HOW confident — factor breakdown explaining confidence score
 *   5. HOW to verify — concrete reproduction/verification steps
 *
 * Rules not in MIGRATED_RULES produce flat evidence strings. During the grace
 * period (EVIDENCE_CHAIN_GRACE_PERIOD = true in relevance.ts), these still
 * affect the score. When the grace period ends, only rules with evidence
 * chains will produce scored findings.
 */

/** Rules that produce structured EvidenceChain objects */
export const MIGRATED_RULES: ReadonlySet<string> = new Set([
  "C1", // command injection — AST taint + verification steps (reference implementation)
  "A1", // prompt injection in description — linguistic scoring + verification
  "C5", // hardcoded secrets — entropy + token prefix + verification
  "G1", // indirect prompt injection gateway — content ingestion + cross-tool flow
  "H2", // initialize response injection — pattern match + session-hijack impact
  "F1", // lethal trifecta — capability graph / schema structural + data flow verification
]);

/** Check if a rule has been migrated to produce evidence chains */
export function isMigrated(ruleId: string): boolean {
  return MIGRATED_RULES.has(ruleId);
}

/** Get migration progress summary */
export function migrationProgress(): {
  total: number;
  migrated: number;
  percent: number;
} {
  const migrated = MIGRATED_RULES.size;
  return {
    total: 177,
    migrated,
    percent: Math.round((migrated / 177) * 100),
  };
}
