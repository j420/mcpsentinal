/**
 * M6 — Progressive Context Poisoning Enablers (Rule Standard v2).
 *
 * Structural / line-level detector. Never fires on test files or files
 * <50 lines. Skips sources with a nearby bound keyword (present=true
 * mitigation + lower confidence).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherM6, type AccumulationSite } from "./gather.js";
import { M6_CONFIDENCE_CAP } from "./data/accumulation-surfaces.js";
import {
  buildAccumulationInspectionStep,
  buildBoundCheckStep,
  buildFeedbackLoopTraceStep,
} from "./verification.js";

const RULE_ID = "M6";
const RULE_NAME = "Progressive Context Poisoning Enablers";
const OWASP = "ASI06-memory-context-poisoning" as const;
const MITRE = "AML.T0058";

const REMEDIATION =
  "Bound the accumulation: apply a size limit, max length, TTL, or " +
  "explicit truncation step to any context / memory / history buffer that " +
  "holds content the agent later re-reads. Attach a provenance / integrity " +
  "check between the write and the read (signed entries, per-entry " +
  "source attribution) so poisoned writes can be filtered at read time. " +
  "For vector stores, tag embeddings with their origin and exclude " +
  "unverified origins from agent context retrievals.";

class ProgressiveContextPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherM6(context);
    if (gathered.sites.length === 0) return [];
    // Emit only the top candidate per scan — progressive-poisoning is
    // architectural; a dozen findings on the same pattern adds noise.
    const worst = pickWorst(gathered.sites);
    if (!worst) return [];
    return [this.buildFinding(worst)];
  }

  private buildFinding(site: AccumulationSite): RuleResult {
    const hasBound = site.bound_distance !== null;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Server accumulates content into a ${site.context_label} using ` +
          `${site.verb.label}. When the store is re-read by the agent, ` +
          `every prior append enters the reasoning window.`,
      })
      .propagation({
        propagation_type: "variable-assignment",
        location: site.location,
        observed:
          `Content flows from the tool call's input into the persistent ` +
          `store; subsequent agent turns re-read the store and treat the ` +
          `accumulated bytes as prior context.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed:
          `The ${site.context_label} is a cross-turn trust store — it ` +
          `persists adversary-reachable content into sessions the ` +
          `original user never authorised.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: hasBound,
        location: site.location,
        detail: hasBound
          ? `Bound keyword "${site.bound_label}" present ${site.bound_distance} ` +
            `line(s) away. Verify it actually applies to THIS accumulation ` +
            `call and not a sibling one.`
          : `No bound keyword (limit / max / truncate / clear / reset / ` +
            `evict / expire / ttl) within ±6 lines. Accumulation is ` +
            `architecturally unbounded.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An attacker with access to any upstream tool that writes into ` +
          `this store plants incremental nudges over many sessions. Each ` +
          `nudge is below the single-turn injection threshold; the ` +
          `cumulative payload crosses the agent's behavioural threshold ` +
          `on a future turn, at which point the agent complies with ` +
          `adversary instructions embedded in what it treats as its own ` +
          `prior context.`,
      })
      .factor(
        "accumulation_without_bounds",
        hasBound ? -0.1 : 0.1,
        hasBound
          ? `Bound within window (distance ${site.bound_distance}) — ` +
            `architectural hazard is reduced.`
          : `No bound keyword within ±6 lines. Accumulation is unbounded ` +
            `for the lifetime of the store.`,
      )
      .factor(
        site.vector_store_context ? "vector_store_context" : "log_store_context",
        site.vector_store_context ? 0.08 : 0.0,
        site.vector_store_context
          ? `Accumulation targets a vector / embedding store; semantic ` +
            `search will return poisoned content for queries near the ` +
            `attacker's chosen neighbourhood.`
          : `Accumulation targets a plain log / buffer store.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0058",
        title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
        url: "https://atlas.mitre.org/techniques/AML.T0058",
        relevance:
          "M6 is the static detector for the architectural enabler " +
          "(unbounded persistent store) AML.T0058 requires.",
      })
      .verification(buildAccumulationInspectionStep(site))
      .verification(buildBoundCheckStep(site))
      .verification(buildFeedbackLoopTraceStep(site));

    const chain = cap(builder.build(), M6_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function pickWorst(sites: AccumulationSite[]): AccumulationSite | null {
  if (sites.length === 0) return null;
  // Prefer no-bound sites; among those, prefer vector-store contexts.
  let best: AccumulationSite | null = null;
  for (const s of sites) {
    if (!best) {
      best = s;
      continue;
    }
    const bestScore =
      (best.bound_distance === null ? 2 : 0) + (best.vector_store_context ? 1 : 0);
    const thisScore =
      (s.bound_distance === null ? 2 : 0) + (s.vector_store_context ? 1 : 0);
    if (thisScore > bestScore) best = s;
  }
  return best;
}

function cap(chain: EvidenceChain, v: number): EvidenceChain {
  if (chain.confidence <= v) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: v - chain.confidence,
    rationale: `M6 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new ProgressiveContextPoisoningRule());

export { ProgressiveContextPoisoningRule };
