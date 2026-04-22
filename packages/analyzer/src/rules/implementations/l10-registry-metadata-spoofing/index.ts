/** L10 — Registry Metadata Spoofing (v2). Structural JSON + AST; zero regex; cap 0.80. */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherL10, type SpoofSite } from "./gather.js";
import {
  stepInspectField,
  stepCheckPublisher,
  stepCheckNamespace,
} from "./verification.js";

const RULE_ID = "L10";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0017" as const;
const CONFIDENCE_CAP = 0.80;

const REMEDIATION =
  "Do not impersonate vendor identities in package metadata (author, " +
  "publisher, organization, maintainer). If the package is an independent " +
  "integration, name the author honestly. If it is an official vendor " +
  "package, publish it under the vendor's npm/PyPI organization namespace " +
  "so the registry attests to authorship rather than the description.";

const REF_COSAI_T6 = {
  id: "CoSAI-MCP-T6",
  title: "CoSAI MCP Security — T6: Supply Chain Integrity",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "Package metadata must accurately reflect authorship. Vendor impersonation " +
    "enables supply chain attacks by building on trust in a third party.",
} as const;

class L10Rule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = "Registry Metadata Spoofing";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const sites = gatherL10(context);
    return sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: SpoofSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: `${site.field}: "${site.observed}"`,
        rationale:
          `Package metadata field "${site.field}" claims affiliation with ` +
          `protected vendor "${site.vendor}". If the package is not actually ` +
          `published by ${site.vendor}, this is metadata spoofing.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed: `False vendor attribution: "${site.field}" = "${site.observed}"`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `Developers and AI clients weight vendor attribution when ranking ` +
          `packages. A spoofed "author" gains unearned trust. Combined with ` +
          `typosquatting (D3), this enables supply chain attacks against ` +
          `agents that auto-install MCP servers.`,
      })
      .factor(
        "vendor_in_author_field",
        0.12,
        `Protected vendor "${site.vendor}" claimed in "${site.field}" field`,
      );

    builder.reference(REF_COSAI_T6);
    builder.verification(stepInspectField(site));
    builder.verification(stepCheckPublisher(site));
    builder.verification(stepCheckNamespace(site));

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
    rationale: `L10 cap ${cap}: static metadata does not prove impersonation; registry cross-check required.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new L10Rule());
export { L10Rule };
