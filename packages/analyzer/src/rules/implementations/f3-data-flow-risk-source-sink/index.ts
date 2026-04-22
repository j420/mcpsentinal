/**
 * F3 — Data Flow Risk: Source → Sink (v2 stub — companion of F1).
 *
 * F3 findings are emitted by F1's `analyze()` as a by-product of the
 * capability-graph / schema-inference pass that detects the lethal
 * trifecta. A standalone F3 analyze() would need to rebuild the
 * capability graph that F1 has already constructed — duplicated work,
 * identical output.
 *
 * This stub exists so the engine's TypedRule dispatcher does not warn
 * about a missing registration for "F3". See CHARTER.md in this
 * directory for the full companion-pattern rationale.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";

class F3CompanionStub implements TypedRuleV2 {
  readonly id = "F3";
  readonly name = "Data Flow Risk Source→Sink (companion of F1)";
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "stub";

  analyze(_context: AnalysisContext): RuleResult[] {
    // Parent rule F1 produces F3 findings. See
    // f1-lethal-trifecta/index.ts buildCompanionFinding().
    return [];
  }
}

registerTypedRuleV2(new F3CompanionStub());

export { F3CompanionStub };
