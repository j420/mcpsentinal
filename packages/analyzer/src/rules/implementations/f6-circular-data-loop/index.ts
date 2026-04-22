/**
 * F6 — Circular Data Loop (v2 stub — companion of F1).
 *
 * F6 detects persistent prompt injection via a shared data store: a
 * writes-data node in a cycle with a reads-private-data (or
 * reads-public-data) node. Attacker poisons the store once; the agent
 * re-reads the poisoned content on every subsequent session.
 *
 * F1's `analyze()` is the canonical emitter of F6 findings — its
 * capability-graph pass already runs DFS cycle detection and filters
 * cycles for the write+read pattern. A standalone F6 detector would
 * rebuild the graph and repeat the DFS.
 *
 * This stub exists so the engine's TypedRule dispatcher does not warn
 * about a missing registration for "F6". See CHARTER.md in this
 * directory for why F6 is a signature MCP Sentinel detection.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";

class F6CompanionStub implements TypedRuleV2 {
  readonly id = "F6";
  readonly name = "Circular Data Loop (companion of F1)";
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "stub";

  analyze(_context: AnalysisContext): RuleResult[] {
    // Parent rule F1 produces F6 findings when its capability-graph cycle
    // detection surfaces a write+read loop. See
    // f1-lethal-trifecta/index.ts buildCompanionFinding().
    return [];
  }
}

registerTypedRuleV2(new F6CompanionStub());

export { F6CompanionStub };
