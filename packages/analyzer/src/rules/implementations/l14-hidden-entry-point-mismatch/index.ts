/**
 * L14 — Hidden Entry Point Mismatch (Rule Standard v2).
 *
 * STUB TypedRuleV2. L14 findings are emitted by the parent L5 rule
 * (`l5-manifest-confusion/index.ts`) during its single package-
 * manifest analysis pass. This file exists so:
 *
 *   - the engine's "typed rule has no TypeScript implementation"
 *     warning does not fire for L14;
 *   - charter-traceability finds a CHARTER.md + matching index.ts
 *     pair for every active rule;
 *   - a future rule engineer who wants to un-stub L14 has a clear
 *     skeleton to fill in (see CHARTER.md §"When to un-stub").
 *
 * Rationale for the companion pattern (same reasoning as I2 and
 * F2/F3/F6 in wave-2): running a second AST walk here to re-emit
 * findings the parent already computes would double the cost
 * without changing the evidence.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";

const RULE_ID = "L14";
const RULE_NAME = "Hidden Entry Point Mismatch (via L5)";

class HiddenEntryPointMismatchStub implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "stub";

  analyze(_context: AnalysisContext): RuleResult[] {
    // Intentionally empty. The parent L5 rule produces all L14 findings
    // during its manifest scan. Re-emitting them here would double-count.
    return [];
  }
}

registerTypedRuleV2(new HiddenEntryPointMismatchStub());

export { HiddenEntryPointMismatchStub };
