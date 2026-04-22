import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN11, type DowngradeSite } from "./gather.js";
import { N11_CONFIDENCE_CAP } from "./data/n11-config.js";
import {
  SECURITY_FEATURE_INTRODUCED,
} from "../_shared/mcp-method-catalogue.js";
import {
  buildEchoInspectionStep,
  buildEnforcementCheckStep,
  buildFeatureLossTraceStep,
} from "./verification.js";

const RULE_ID = "N11";
const RULE_NAME = "Protocol Version Downgrade Attack";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Enforce a minimum protocolVersion using an ordered comparator (see " +
  "_shared/mcp-method-catalogue.ts SPEC_VERSION_ORDER). Reject initialize " +
  "requests that propose a version below the minimum. Never reflect the " +
  "client-proposed version verbatim. Document the minimum in the server's " +
  "README so clients are aware.";

class ProtocolVersionDowngradeRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN11(context);
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: DowngradeSite): RuleResult {
    const features = Object.entries(SECURITY_FEATURE_INTRODUCED)
      .map(([f, v]) => `${f}@${v}`)
      .join(", ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Server's version-negotiation path (${site.echo_label}) accepts ` +
          `the client-proposed protocolVersion without comparing against a ` +
          `minimum. This is the TLS-downgrade-class vulnerability at the ` +
          `MCP layer.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Client-proposed version flows verbatim into the initialize ` +
          `response; the effective negotiated version becomes whatever the ` +
          `client chose.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed:
          `Downgrade to 2024-11-05 silently removes the security features ` +
          `introduced in later revisions: ${features}.`,
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: site.enforcement_present,
        location: site.location,
        detail: site.enforcement_present
          ? `Enforcement "${site.enforcement_label}" nearby (${site.enforcement_distance} ` +
            `lines away) — confirm it actually rejects below-minimum versions.`
          : `No enforcement keyword within the window. Downgrade unrejected.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An attacker-controlled client negotiates protocolVersion= ` +
          `'2024-11-05'. The server agrees. Tool annotations (readOnlyHint / ` +
          `destructiveHint / idempotentHint / openWorldHint) added in ` +
          `2025-03-26 disappear from the conversation; the client cannot ` +
          `enforce them because the server's handshake promised to speak ` +
          `the older protocol. Every auto-approval path the annotations ` +
          `were supposed to gate is now armed at the default risk level.`,
      })
      .factor(
        "version_enforcement_absent",
        site.enforcement_present ? -0.1 : 0.1,
        site.enforcement_present
          ? `Enforcement nearby — confirm coverage.`
          : `No enforcement within ±8 lines. Downgrade is accepted.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — Prompt Injection (version-downgrade variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N11 detects the version-downgrade variant: selecting an older " +
          "protocol to strip safety controls the attacker benefits from " +
          "being absent.",
      })
      .verification(buildEchoInspectionStep(site))
      .verification(buildEnforcementCheckStep(site))
      .verification(buildFeatureLossTraceStep(site));

    const chain = cap(builder.build(), N11_CONFIDENCE_CAP);
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
    rationale: `N11 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new ProtocolVersionDowngradeRule());

export { ProtocolVersionDowngradeRule };
