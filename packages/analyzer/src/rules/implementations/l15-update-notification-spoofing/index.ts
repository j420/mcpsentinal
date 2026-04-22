/** L15 — Update Notification Spoofing (v2). AST + token walker; zero regex; cap 0.80. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherL15, type SpoofSite } from "./gather.js";
import {
  stepInspectLiteral,
  stepCheckLegitimate,
  stepCheckExecPath,
} from "./verification.js";

const RULE_ID = "L15";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Never display hand-rolled update notifications that ship an install " +
  "command. Use a well-known update-notifier library that verifies the ` + " +
  "latest version against the official registry, and present the command " +
  "as reference text — never include the install command inside a user-" +
  "facing prompt that encourages copy-paste.";

const REF_OWASP_ASI04 = {
  id: "OWASP-ASI04",
  title: "OWASP Agentic Top 10 — ASI04: Agentic Supply Chain",
  url: "https://owasp.org/www-project-agentic-security-initiative/",
  relevance:
    "Fake update notifications are a supply chain social-engineering vector " +
    "aimed at both human operators and autonomous agents that run shell commands.",
} as const;

class L15Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = "Update Notification Spoofing";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherL15(context);
    return sites
      .filter((s) => !s.enclosing_has_legitimate_idiom)
      .map((s) => this.buildFinding(s));
  }

  private buildFinding(site: SpoofSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.observed,
        rationale:
          `String literal at this location combines "${site.notification_desc}" ` +
          `language with "${site.install_evidence}". The pattern is a fake ` +
          `update notification that encourages users (or agents) to run an ` +
          `install command that may install attacker-controlled code.`,
      })
      .sink({
        sink_type: "command-execution",
        location: site.location,
        observed: `Install command embedded in notification string`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: site.enclosing_has_legitimate_idiom,
        location: site.location,
        detail: site.enclosing_has_legitimate_idiom
          ? `Enclosing scope references a real update-checker library.`
          : `No legitimate update-checker library found in scope.`,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          `User or automated agent reads the fake update message, runs the ` +
          `embedded install command, and installs an attacker-controlled ` +
          `package. Supply-chain compromise completes silently.`,
      })
      .factor(
        "notification_plus_install",
        0.15,
        `Notification + install coexist in the same literal`,
      );

    builder.reference(REF_OWASP_ASI04);
    builder.verification(stepInspectLiteral(site));
    builder.verification(stepCheckLegitimate(site));
    builder.verification(stepCheckExecPath(site));

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
    rationale: `L15 cap ${cap}: static scan cannot prove the string reaches a user-facing surface.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new L15Rule());
export { L15Rule };
