/**
 * C3 — SSRF: gather facts via the shared taint-rule-kit.
 *
 * Thin wrapper that configures the kit with C3-specific sink categories
 * and charter-audited sanitisers. All orchestration — AST taint then
 * lightweight taint fallback, test-file suppression, Location-kinded
 * structured facts — lives in the shared kit.
 *
 * Zero regex in this file.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  gatherTaintFacts,
  type TaintGatherResult,
} from "../_shared/taint-rule-kit/index.js";
import {
  C3_AST_SINK_CATEGORIES,
  C3_LIGHTWEIGHT_SINK_CATEGORIES,
  C3_CHARTER_SANITISERS,
} from "./data/config.js";

export function gatherC3(context: AnalysisContext): TaintGatherResult {
  return gatherTaintFacts(context, {
    ruleId: "C3",
    astSinkCategories: C3_AST_SINK_CATEGORIES,
    lightweightSinkCategories: C3_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: C3_CHARTER_SANITISERS,
  });
}
