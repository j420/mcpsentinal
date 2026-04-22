/** O4 — Timing-Based Data Inference (v2). AST-based, zero regex, cap 0.85. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherO4, type TimingSite } from "./gather.js";
import {
  stepInspectDelay,
  stepCheckTimingSafe,
  stepCheckJitter,
} from "./verification.js";

const RULE_ID = "O4";
const RULE_NAME = "Timing-Based Data Inference";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Replace data-dependent branching around delay calls with constant-time " +
  "primitives: crypto.timingSafeEqual (Node), hmac.compare_digest (Python), " +
  "or an explicit additive Math.random jitter calibrated above the branch's " +
  "measurable delta. Avoid setTimeout/sleep inside if/else arms that depend " +
  "on sensitive identifiers.";

const REF_MITRE = {
  id: "MITRE-AML-T0057",
  title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
  url: "https://atlas.mitre.org/techniques/AML.T0057",
  relevance:
    "Timing side channels leak information about sensitive branching via " +
    "observable response-time variation.",
} as const;

class O4Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const files = context.source_files ?? new Map([["scan.ts", context.source_code ?? ""]]);
    const findings: RuleResult[] = [];

    for (const [file, text] of files) {
      if (!text) continue;
      const localCtx: AnalysisContext = { ...context, source_code: text };
      const sites = gatherO4(localCtx, file);
      for (const site of sites) {
        if (site.hasTimingSafe || site.hasJitter) continue;
        findings.push(this.buildFinding(site));
      }
    }
    return findings;
  }

  private buildFinding(site: TimingSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `A ${site.delayKind} call (\`${site.delayCallee}\`) sits inside a ` +
          `function that reads sensitive identifiers. The delay magnitude ` +
          `thus varies with internal data, producing an observable timing ` +
          `side channel.`,
      })
      .propagation({
        propagation_type: "variable-assignment",
        location: site.location,
        observed: "Data-dependent branch governs delay duration",
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed: `Observable response-time variation via ${site.delayCallee}()`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: site.enclosingFunctionLocation ?? site.location,
        detail:
          `No constant-time primitive (timingSafeEqual / compare_digest / ` +
          `constantTime) and no Math.random jitter were found in the ` +
          `enclosing function scope.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "complex",
        scenario:
          `Attacker sends repeated requests and measures response-time ` +
          `deltas. Over many samples the mean delay converges to a value ` +
          `that depends on the comparison outcome — leaking the existence ` +
          `of a user, a character match in a secret, or a role boundary.`,
      })
      .factor("delay_in_conditional", 0.10, `Delay call "${site.delayCallee}" inside data-dependent function`)
      .factor("no_timing_safe", 0.08, "No constant-time primitive in enclosing scope");

    builder.reference(REF_MITRE);
    builder.verification(stepInspectDelay(site));
    builder.verification(stepCheckTimingSafe(site));
    builder.verification(stepCheckJitter(site));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `O4 charter caps confidence at ${cap}: static reasoning cannot prove timing delta is observable.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new O4Rule());
export { O4Rule };
