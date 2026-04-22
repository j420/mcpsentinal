/**
 * A8 — Description-Capability Mismatch (Rule Standard v2).
 *
 * Detects "read-only"/"safe"/"non-destructive" claims in the tool
 * description paired with write-capable parameters, network-send
 * parameters, or dangerous defaults in the input_schema. Linguistic
 * claim match + structural parameter analysis. No regex literals.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gatherA8, toolLocation, type MismatchSite } from "./gather.js";
import { stepInspectClaim, stepInspectSchema } from "./verification.js";

const RULE_ID = "A8";
const RULE_NAME = "Description-Capability Mismatch";
const OWASP = "MCP02-tool-poisoning";
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Update the description to accurately reflect the tool's capabilities. If the " +
  "claim is aspirational (\"future versions will be read-only\"), remove it until " +
  "the claim is true. If the claim is current, remove the write/network/dangerous-" +
  "default parameters or rename them to reflect their read-only role. Deceptive " +
  "labelling shapes AI auto-approval decisions and is a top-3 trust-boundary " +
  "violation per Trail of Bits (2026).";

class A8DescriptionCapabilityMismatchRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "composite"; // linguistic + structural

  analyze(context: AnalysisContext): RuleResult[] {
    return gatherA8(context).map((s) => this.buildFinding(s));
  }

  private buildFinding(site: MismatchSite): RuleResult {
    const loc = toolLocation(site.tool_name);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: `Claim: "${site.claim.observed}"`,
        rationale:
          `Tool "${site.tool_name}" description advertises ${site.claim.label} — a ` +
          `claim AI clients use to shape auto-approval decisions. The claim is ` +
          `contradicted by the tool's input schema.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: loc,
        observed:
          `Schema reveals write-capable parameters [${site.write_params.join(", ") || "-"}], ` +
          `network-send parameters [${site.network_params.join(", ") || "-"}], and ` +
          `dangerous defaults [${site.dangerous_defaults.map((d) => d.name).join(", ") || "-"}].`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: loc,
        observed:
          `AI auto-approves the tool under the false "${site.claim.label}" banner; ` +
          `the real capabilities (write / network / destructive defaults) execute ` +
          `without confirmation.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `A user relies on the description's safety claim. The AI selects and ` +
          `invokes the tool; the deceptive labelling caused the user and the AI to ` +
          `extend trust the schema reveals was never warranted.`,
      })
      .factor(
        "claim_parameter_mismatch",
        0.12,
        `Claim "${site.claim.label}" contradicted by ${
          site.write_params.length + site.network_params.length + site.dangerous_defaults.length
        } capability signal(s).`,
      );

    if (site.dangerous_defaults.length > 0) {
      builder.factor(
        "destructive_defaults_present",
        0.10,
        `${site.dangerous_defaults.length} parameter(s) default to permissive values ` +
          `(${site.dangerous_defaults.map((d) => d.label).join(", ")}).`,
      );
    }

    builder.reference({
      id: "TRAIL-OF-BITS-TRUST-BOUNDARIES-2026",
      title: "Trail of Bits (2026) — Trust boundaries in agentic AI systems",
      url: "https://blog.trailofbits.com/2026/02/trust-boundaries-agentic-ai/",
      relevance:
        "Description-capability mismatch is named a top-3 trust-boundary violation " +
        "pattern — the AI's privilege model is shaped by the description, not the " +
        "implementation.",
    });

    builder.verification(stepInspectClaim(site));
    builder.verification(stepInspectSchema(site));

    const chain = builder.build();
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "composite_scoring_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale: `A8 charter caps confidence at ${CONFIDENCE_CAP}.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

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

registerTypedRuleV2(new A8DescriptionCapabilityMismatchRule());

export { A8DescriptionCapabilityMismatchRule };
