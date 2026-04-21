/**
 * C4 — SQL Injection: gather facts via the shared taint-rule-kit.
 *
 * Thin wrapper that configures the kit with C4-specific sink categories
 * and charter-audited sanitisers. All orchestration — AST taint then
 * lightweight taint fallback, test-file suppression, Location-kinded
 * structured facts — lives in the shared kit.
 *
 * Zero regex in this file.
 */

import type { AnalysisContext } from "../../../engine.js";
import { gatherTaintFacts, type TaintGatherResult } from "../_shared/taint-rule-kit/index.js";
import {
  C4_AST_SINK_CATEGORIES,
  C4_LIGHTWEIGHT_SINK_CATEGORIES,
  C4_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC4(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C4",
    astSinkCategories: C4_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C4_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C4_CHARTER_SANITISERS,
  });
}
