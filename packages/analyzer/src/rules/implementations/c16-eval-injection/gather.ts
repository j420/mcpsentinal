/**
 * C16 — Dynamic Code Evaluation: gather facts via the shared taint-rule-kit.
 */

import type { AnalysisContext } from "../../../engine.js";
import { gatherTaintFacts, type TaintGatherResult } from "../_shared/taint-rule-kit/index.js";
import {
  C16_AST_SINK_CATEGORIES,
  C16_LIGHTWEIGHT_SINK_CATEGORIES,
  C16_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC16(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C16",
    astSinkCategories: C16_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C16_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C16_CHARTER_SANITISERS,
  });
}
