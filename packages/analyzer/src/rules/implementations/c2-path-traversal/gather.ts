/**
 * C2 — Path Traversal: gather facts via the shared taint-rule-kit.
 *
 * Primary mode: delegates to the shared taint-rule-kit which runs
 * analyzeASTTaint and then analyzeTaint. The kit emits uniform
 * TaintFact[] which index.ts converts to v2 RuleResults.
 *
 * Zero regex literals. Zero string-literal arrays > 5 in this file.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  gatherTaintFacts,
  type TaintGatherResult,
} from "../_shared/taint-rule-kit/index.js";
import {
  C2_AST_SINK_CATEGORIES,
  C2_LIGHTWEIGHT_SINK_CATEGORIES,
  C2_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC2(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C2",
    astSinkCategories: C2_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C2_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C2_CHARTER_SANITISERS,
  });
}
