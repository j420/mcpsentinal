/**
 * J2 — Git Argument Injection: fact gatherer.
 *
 * Uses the shared taint-rule-kit to obtain command_execution flows,
 * then post-filters to ONLY those whose sink text identifies a git
 * invocation. The filter distinguishes J2 from C1: C1 covers generic
 * command injection, J2 covers git-specific argument injection where
 * the CVE chain (68143/68144/68145) demonstrates specific-flag exploits.
 *
 * Additional structural signals — dangerous git flags, sensitive paths —
 * are recorded on the fact so index.ts can tune the severity and
 * confidence factors appropriately.
 *
 * No regex. All detection data lives in `./data/config.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  gatherTaintFacts,
  type TaintGatherResult,
  type TaintFact,
} from "../_shared/taint-rule-kit/index.js";
import {
  J2_AST_SINK_CATEGORIES,
  J2_LIGHTWEIGHT_SINK_CATEGORIES,
  J2_CHARTER_SANITISERS,
  J2_GIT_MARKERS,
  J2_DANGEROUS_FLAG_MARKERS,
  J2_SENSITIVE_PATH_MARKERS,
} from "./data/config.js";

/** Enhanced fact tagging which git-family signals are present. */
export interface J2Fact extends TaintFact {
  dangerousFlag: string | null;
  sensitivePath: string | null;
}

export interface J2GatherResult {
  mode: TaintGatherResult["mode"];
  facts: J2Fact[];
}

export function gatherJ2(context: AnalysisContext): J2GatherResult {
  const gathered = gatherTaintFacts(context, {
    ruleId: "J2",
    astSinkCategories: J2_AST_SINK_CATEGORIES,
    lightweightSinkCategories: J2_LIGHTWEIGHT_SINK_CATEGORIES,
    charterSanitisers: J2_CHARTER_SANITISERS,
  });

  if (gathered.mode !== "facts") {
    return { mode: gathered.mode, facts: [] };
  }

  // Post-filter: keep only taint facts whose sink OR any propagation hop
  // mentions git. Flows like `const cmd = "git diff " + x; exec(cmd)` have
  // the git marker in a propagation hop, not the sink expression itself.
  const gitFacts: J2Fact[] = [];
  for (const fact of gathered.facts) {
    const sinkHasGit = hasGitMarker(fact.sinkExpression);
    const hopHasGit = fact.path.some((step) => hasGitMarker(step.expression));
    if (!sinkHasGit && !hopHasGit) continue;

    // Scan both the sink expression and the propagation hop expressions
    // for dangerous flag / sensitive path markers — the exploit signature
    // can land on either surface.
    const combined = fact.sinkExpression + " " + fact.path.map((s) => s.expression).join(" ");
    gitFacts.push({
      ...fact,
      dangerousFlag: firstMarkerIn(combined, J2_DANGEROUS_FLAG_MARKERS),
      sensitivePath: firstMarkerIn(combined, J2_SENSITIVE_PATH_MARKERS),
    });
  }

  return { mode: gitFacts.length > 0 ? "facts" : "absent", facts: gitFacts };
}

function hasGitMarker(text: string): boolean {
  for (const marker of J2_GIT_MARKERS) {
    if (text.includes(marker)) return true;
  }
  return false;
}

function firstMarkerIn(text: string, markers: readonly string[]): string | null {
  for (const m of markers) {
    if (text.includes(m)) return m;
  }
  return null;
}
