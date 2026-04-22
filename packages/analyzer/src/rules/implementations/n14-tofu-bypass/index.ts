import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN14, type TofuSite } from "./gather.js";
import { N14_CONFIDENCE_CAP } from "./data/n14-config.js";
import {
  buildSiteInspectionStep,
  buildBypassImpactStep,
  buildRemediationStep,
} from "./verification.js";

const RULE_ID = "N14";
const RULE_NAME = "Trust-On-First-Use Bypass (TOFU)";
const OWASP = "MCP10-supply-chain" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Pre-distribute server fingerprints out-of-band (pre-shared, registry-" +
  "signed, or CA-signed). When TOFU is unavoidable, require explicit " +
  "operator confirmation on first-pin AND reject any subsequent mismatch " +
  "rather than silently re-pinning. Do not ship flags that disable " +
  "fingerprint verification.";

class TOFUBypassRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN14(context);
    if (!g.tofu_context_present) return [];
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: TofuSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Line ${site.line} contains ${site.fragment_label}, a known TOFU-` +
          `bypass anti-pattern (${site.variant.replace("_", "-")}). TOFU's ` +
          `security depends on a rigid first-pin followed by strict ` +
          `rejection on mismatch — both fail under the observed code shape.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          site.variant === "pinning_bypass"
            ? `Bypass flag flows into the verification path, disabling the ` +
              `integrity check that TOFU was designed around.`
            : `Accept-any / auto-pin flows into the trust store, which ` +
              `accepts the first identity presented as the "real" server.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed:
          `Attacker-supplied server identity is accepted as authoritative; ` +
          `every subsequent tools/list and tools/call response is treated as ` +
          `from the legitimate server.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: site.location,
        detail:
          `Identity verification is bypassed or circumvented. No effective ` +
          `integrity-of-identity mitigation is in force at this site.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          site.variant === "pinning_bypass"
            ? `An attacker performs an identity-swap MITM between two ` +
              `client connects. Since pinning is bypassed, the client does ` +
              `not notice. Every subsequent tool invocation runs against ` +
              `the attacker's impersonated server.`
            : `An attacker positioned at the first connect plants their own ` +
              `identity in the pin store. Every subsequent connection ` +
              `verifies against the attacker's identity.`,
      })
      .factor(
        "pinning_bypass_detected",
        0.12,
        `Observed anti-pattern: ${site.fragment_label} (${site.variant}).`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — Prompt Injection (TOFU-bypass variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N14 detects the TOFU-bypass variant: substitute the server " +
          "identity so every later tools/list is attacker-controlled.",
      })
      .verification(buildSiteInspectionStep(site))
      .verification(buildBypassImpactStep(site))
      .verification(buildRemediationStep(site));

    const chain = cap(builder.build(), N14_CONFIDENCE_CAP);
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
    rationale: `N14 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new TOFUBypassRule());

export { TOFUBypassRule };
