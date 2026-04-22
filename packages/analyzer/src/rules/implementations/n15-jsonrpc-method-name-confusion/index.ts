import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN15, type ConfusionSite } from "./gather.js";
import { N15_CONFIDENCE_CAP } from "./data/n15-config.js";
import {
  buildSiteInspectionStep,
  buildCanonicalComparisonStep,
  buildMitigationStep,
} from "./verification.js";

const RULE_ID = "N15";
const RULE_NAME = "JSON-RPC Method Name Confusion";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Maintain an explicit allowlist of canonical MCP method names (reference " +
  "_shared/mcp-method-catalogue.ts). Reject methods not in the allowlist. " +
  "Normalise method names (trim, lowercase, strip Unicode-confusable " +
  "codepoints) before comparison. Never dispatch via dynamic property " +
  "access on user-controlled keys; use a switch or Map with literal keys.";

class MethodNameConfusionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "similarity";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN15(context);
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: ConfusionSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: site.type === "user_input_dispatch"
          ? "user-parameter"
          : "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Method-name confusion anti-pattern at line ${site.line}: ` +
          `${site.label}. This degrades the routing-layer integrity the ` +
          `entire JSON-RPC dispatch model depends on.`,
      })
      .propagation({
        propagation_type: site.type === "user_input_dispatch"
          ? "variable-assignment"
          : "direct-pass",
        location: site.location,
        observed:
          site.type === "user_input_dispatch"
            ? `Adversary-controlled method-name string flows into the ` +
              `dispatch table lookup.`
            : `Non-canonical handler name lives alongside the spec handler ` +
              `set; client allowlists keyed on canonical names do not block it.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          site.type === "user_input_dispatch"
            ? `Dynamic dispatch invokes an arbitrary registered handler ` +
              `under an attacker-chosen name.`
            : `Confused-deputy handler registration routes on a name ` +
              `visually close to a canonical one.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: site.location,
        detail:
          `No canonical-method allowlist observed adjacent to the dispatch ` +
          `/ registration site.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          site.type === "user_input_dispatch"
            ? `An attacker sends a JSON-RPC request whose method string ` +
              `selects an internal / privileged handler the client never ` +
              `intended to call (e.g. a debug handler, a maintenance ` +
              `handler, or a Python __getattr__ stub).`
            : `An attacker's client invokes the near-canonical method; ` +
              `the server routes to the imposter handler without the ` +
              `client's allowlist raising an alert.`,
      })
      .factor(
        "method_name_confusion_type",
        0.1,
        `Confusion type: ${site.type}.`,
      )
      .factor(
        site.type === "user_input_dispatch"
          ? "user_input_as_dispatch_key"
          : site.type === "near_canonical_method"
            ? `levenshtein_distance_${site.levenshtein_distance}`
            : site.type === "unicode_homoglyph"
              ? "unicode_homoglyph"
              : "dynamic_property_access",
        site.type === "user_input_dispatch" ? 0.15 : 0.08,
        site.type === "user_input_dispatch"
          ? `User input directly dispatches the handler — the highest ` +
            `severity form of the confusion class.`
          : site.type === "near_canonical_method"
            ? `Handler name "${site.observed_name}" is ${site.levenshtein_distance} ` +
              `edit(s) from canonical "${site.nearest_canonical}". Low ` +
              `edit distance implies deliberate confusion.`
            : site.type === "unicode_homoglyph"
              ? `Non-ASCII characters in method name suggest homoglyph ` +
                `substitution.`
              : `Dynamic property access on a user-controlled key reaches ` +
                `prototype pollution and object-property escapes.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — Prompt Injection (method-name variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N15 is the routing-layer variant of AML.T0054: adversary " +
          "influences which handler runs by manipulating the method string.",
      })
      .verification(buildSiteInspectionStep(site))
      .verification(buildCanonicalComparisonStep(site))
      .verification(buildMitigationStep(site));

    const chain = cap(builder.build(), N15_CONFIDENCE_CAP);
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

function cap(chain: EvidenceChain, v: number): EvidenceChain {
  if (chain.confidence <= v) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: v - chain.confidence,
    rationale: `N15 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new MethodNameConfusionRule());

export { MethodNameConfusionRule };
