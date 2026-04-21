/**
 * C4 verification-step builders.
 *
 * Every step carries a structured Location as `target`. The kit's reusable
 * steps cover the universal source → sink → path chain — this module adds
 * C4-specific flavour text (SQL vocabulary) so an auditor reading the
 * chain sees the same language the charter uses.
 *
 * Zero regex. Zero string-literal arrays > 5.
 */

import type { VerificationStep } from "../../../evidence.js";
import {
  type TaintFact,
  stepInspectTaintSource,
  stepInspectTaintSink,
  stepTraceTaintPath,
  stepInspectTaintSanitiser,
} from "../_shared/taint-rule-kit/index.js";

export function stepInspectSqlSource(fact: TaintFact): VerificationStep {
  // Re-export the shared step verbatim — the source-side language is the
  // same across all taint rules.
  return stepInspectTaintSource(fact);
}

export function stepInspectSqlSink(fact: TaintFact): VerificationStep {
  return stepInspectTaintSink(fact, "a SQL query / execute / raw call");
}

export function stepTraceSqlPath(fact: TaintFact): VerificationStep {
  return stepTraceTaintPath(fact);
}

export function stepInspectSqlSanitiser(fact: TaintFact): VerificationStep | null {
  return stepInspectTaintSanitiser(fact);
}
