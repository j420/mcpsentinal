/**
 * F2 — High-Risk Capability Profile (v2 stub — companion of F1).
 *
 * F2 is emitted as a companion finding by F1's `analyze()`. The parent
 * rule's capability-graph + schema-inference pass detects both patterns
 * (command-injection chain, unrestricted-access) that map to F2 and
 * produces fully-formed evidence chains with `rule_id: "F2"`.
 *
 * This stub exists so the engine's TypedRule dispatcher does not warn
 * about a missing registration for "F2". A standalone F2 analyze()
 * would have to rebuild the entire capability graph to produce the
 * same findings F1 already emits — wasted work with no new signal.
 *
 * See:
 *   - packages/analyzer/src/rules/implementations/f1-lethal-trifecta/index.ts
 *     (canonical emitter of F2 findings)
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

class F2CompanionStub implements TypedRuleV2 {
  readonly id = "F2";
  readonly name = "High-Risk Capability Profile (companion of F1)";
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "stub";

  analyze(_context: AnalysisContext): RuleResult[] {
    // Parent rule F1 produces F2 findings. See
    // f1-lethal-trifecta/index.ts buildCompanionFinding().
    return [];
  }
}

registerTypedRuleV2(new F2CompanionStub());

export { F2CompanionStub };
