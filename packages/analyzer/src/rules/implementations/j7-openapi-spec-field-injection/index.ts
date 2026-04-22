/**
 * J7 — OpenAPI Specification Field Injection (Rule Standard v2).
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
import type { Location } from "../../location.js";
import { gatherJ7, type J7Hit } from "./gather.js";
import { J7_CONFIDENCE_CAP } from "./data/config.js";
import { stepInspectTemplate, stepTraceSpecOrigin } from "./verification.js";

const RULE_ID = "J7";
const RULE_NAME = "OpenAPI Spec Field Injection";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Sanitise OpenAPI spec fields before using them in generated code. " +
  "Prefer AST-building (TypeScript compiler API) over template literals " +
  "or string concatenation. Validate operationId against a strict " +
  "identifier grammar ([A-Za-z_][A-Za-z0-9_]*) before emitting. Hash-" +
  "verify the spec source (signed manifest or SRI hash). Reference " +
  "CVE-2026-22785 and CVE-2026-23947 (Orval MCP generator).";

class OpenApiSpecFieldInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherJ7(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: J7Hit): RuleResult {
    const loc: Location = {
      kind: "source",
      file: "<server source>",
      line: hit.line_number,
    };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: loc,
        observed: hit.line_preview,
        rationale:
          `OpenAPI spec field "${hit.field_spec.field}" is interpolated into ` +
          `generated code via ${hit.marker_spec.kind}. ` +
          `${hit.field_spec.risk_description}`,
      })
      .propagation({
        propagation_type: "template-literal",
        location: loc,
        observed: `Interpolation marker: "${hit.marker_spec.token}".`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: loc,
        observed:
          "Spec field → generated code. No sanitiser observed on this line.",
        cve_precedent: hit.field_spec.cve,
      })
      .impact({
        impact_type: "remote-code-execution",
        scope: "server-host",
        exploitability: "moderate",
        scenario:
          "An attacker publishes a poisoned OpenAPI spec to a registry / " +
          "CDN / caching proxy. When the generator runs against the spec, " +
          "the unsanitised spec field is interpolated into a template " +
          "literal, executing arbitrary code in the generated MCP server. " +
          "CVE-2026-22785 and CVE-2026-23947 demonstrated this against " +
          "Orval's MCP generator.",
      })
      .factor(
        "spec_field_interpolation",
        0.1,
        `Spec field "${hit.field_spec.field}" appears with interpolation ` +
          `marker "${hit.marker_spec.token}" (${hit.marker_spec.kind}) on ` +
          `the same line — matches ${hit.field_spec.cve} pattern.`,
      )
      .reference({
        id: hit.field_spec.cve,
        title:
          hit.field_spec.cve === "CVE-2026-23947"
            ? "Orval MCP generator operationId injection"
            : "Orval OpenAPI → MCP generator summary/description injection",
        url: `https://nvd.nist.gov/vuln/detail/${hit.field_spec.cve}`,
        year: 2026,
        relevance:
          "Canonical real-world CVE for OpenAPI-spec-field-to-generated-" +
          "code injection in MCP tooling.",
      })
      .verification(stepInspectTemplate(hit))
      .verification(stepTraceSpecOrigin(hit));

    const chain = capConfidence(builder.build(), J7_CONFIDENCE_CAP);
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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `J7 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new OpenApiSpecFieldInjectionRule());

export { OpenApiSpecFieldInjectionRule };
