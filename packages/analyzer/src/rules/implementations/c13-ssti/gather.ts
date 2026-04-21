/**
 * C13 — SSTI: gather facts via the shared taint-rule-kit.
 */

import type { AnalysisContext } from "../../../engine.js";
import { gatherTaintFacts, type TaintGatherResult } from "../_shared/taint-rule-kit/index.js";
import {
  C13_AST_SINK_CATEGORIES,
  C13_LIGHTWEIGHT_SINK_CATEGORIES,
  C13_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC13(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C13",
    astSinkCategories: C13_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C13_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C13_CHARTER_SANITISERS,
  });
}
