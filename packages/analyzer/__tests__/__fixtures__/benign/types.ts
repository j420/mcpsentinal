/**
 * Benign Fixture Types
 *
 * Every benign fixture declares its provenance, a rationale explaining why
 * it is safe (often which rule it is specifically designed to stress-test),
 * a full AnalysisContext, and optionally a whitelist of findings below
 * critical/high severity that are acceptable.
 *
 * CRITICAL/HIGH findings are NEVER allowed on a benign fixture. If one fires,
 * either the fixture accidentally contains a real attack (rewrite it) or a
 * rule has a false positive (report it, do NOT silence it here).
 */
import type { AnalysisContext } from "../../../src/engine.js";

export type BenignBucket =
  | "anthropic-official"
  | "smithery-top"
  | "canonical-non-mcp"
  | "edge-of-spec";

export interface AllowedFinding {
  /** Rule id expected to fire (e.g. "A5", "B4"). */
  rule_id: string;
  /** Maximum severity tolerated for this rule on this fixture. */
  severity: "informational" | "low" | "medium";
  /** One-sentence justification — why this finding is acceptable. */
  reason: string;
}

export interface BenignFixture {
  /** Stable identifier, usually `${bucket}/${short-name}`. */
  id: string;
  /** Provenance category this fixture belongs to. */
  bucket: BenignBucket;
  /** 1–2 sentence rationale — which rules this stresses and why it is safe. */
  why_benign: string;
  /** The analysis context the scanner will see. */
  context: AnalysisContext;
  /**
   * Optional whitelist: rules that MAY produce findings of ≤ medium severity
   * on this fixture without being treated as a failure. critical/high are
   * never allowed, regardless of this list.
   */
  allowed_findings?: AllowedFinding[];
}
