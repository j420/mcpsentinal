/**
 * C12 — Unsafe Deserialization: gather facts via the shared taint-rule-kit.
 */

import type { AnalysisContext } from "../../../engine.js";
import { gatherTaintFacts, type TaintGatherResult } from "../_shared/taint-rule-kit/index.js";
import {
  C12_AST_SINK_CATEGORIES,
  C12_LIGHTWEIGHT_SINK_CATEGORIES,
  C12_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC12(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C12",
    astSinkCategories: C12_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C12_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C12_CHARTER_SANITISERS,
  });
}
