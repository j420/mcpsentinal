/**
 * I2 — Missing Destructive Annotation (v2 stub — companion of I1).
 *
 * I2 findings are emitted by I1's analyze() as a byproduct of the same
 * annotation-vs-schema analysis pass. The stub exists so the engine's
 * TypedRuleV2 dispatcher does not warn about a missing registration
 * for "I2". A standalone I2 analyze() would re-walk the tool set and
 * re-run schema-inference — wasted work with no new signal.
 *
 * See:
 *   - packages/analyzer/src/rules/implementations/i1-annotation-deception/index.ts
 *     (canonical emitter of I2 findings)
 *   - agent_docs/detection-rules.md §"Companion Rule Pattern"
 *   - CHARTER.md in this directory
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";

class I2CompanionStub implements TypedRuleV2 {
  readonly id = "I2";
  readonly name = "Missing Destructive Annotation (companion of I1)";
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "stub";

  analyze(_context: AnalysisContext): RuleResult[] {
    // Parent rule I1 produces I2 findings. See
    // i1-annotation-deception/index.ts when the missing-destructiveHint
    // variant emerges from the same analysis pass. Standalone detection
    // would duplicate the scan.
    return [];
  }
}

registerTypedRuleV2(new I2CompanionStub());

export { I2CompanionStub };
