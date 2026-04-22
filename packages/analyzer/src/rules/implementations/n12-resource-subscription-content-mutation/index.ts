import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN12, type UpdateSite } from "./gather.js";
import { N12_CONFIDENCE_CAP } from "./data/n12-config.js";
import {
  buildEmitInspectionStep,
  buildIntegrityCheckStep,
  buildTOCTOUTraceStep,
} from "./verification.js";

const RULE_ID = "N12";
const RULE_NAME = "Resource Subscription Content Mutation";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0058";

const REMEDIATION =
  "Attach a content hash / signature to every resources/subscribe " +
  "response and re-verify on every resources/updated notification. " +
  "Reject updates that do not match the expected signature. For cross-" +
  "server relays, verify the upstream signature before republishing. " +
  "Do not coalesce updates; deliver every version or emit a synthetic " +
  "tombstone so subscribers can audit the sequence.";

class ResourceSubscriptionPoisoningRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN12(context);
    if (!g.subscription_surface_present) return [];
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: UpdateSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Server emits a resource-update (${site.emit_label}) that ` +
          `subscribers consume as authoritative content. If the update ` +
          `does not carry a matching signature, the subscriber cannot ` +
          `detect that the resource was mutated by an attacker.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Mutated resource content flows through the notification ` +
          `envelope into the subscribed agent's context window.`,
      })
      .sink({
        sink_type: "config-modification",
        location: site.location,
        observed:
          `Agent treats mutated content as trusted (per the original ` +
          `subscribe-time consent). Time-of-check / time-of-use gap ` +
          `invalidates the trust boundary.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: site.integrity_present,
        location: site.location,
        detail: site.integrity_present
          ? `Integrity fragment "${site.integrity_label}" within window — ` +
            `confirm coverage of this emit.`
          : `No integrity fragment within ±6 lines. Subscribers can't ` +
            `detect the content swap.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An attacker with write access to the subscribed resource ` +
          `(shared document, shared config, shared database row) mutates ` +
          `it after subscribe-time. The server pushes the updated content ` +
          `to the agent's context. Because no integrity check is applied, ` +
          `the agent accepts the mutation as a legitimate update to the ` +
          `resource it originally consented to.`,
      })
      .factor(
        "integrity_check_absent",
        site.integrity_present ? -0.1 : 0.1,
        site.integrity_present
          ? `Integrity check nearby — confirm coverage.`
          : `No integrity check within window. Subscribers trust mutated ` +
            `content.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0058",
        title:
          "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning (subscription mutation variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0058",
        relevance:
          "N12 detects the subscription-mutation variant where the trust " +
          "boundary is established at subscribe time and silently " +
          "invalidated by content mutation.",
      })
      .verification(buildEmitInspectionStep(site))
      .verification(buildIntegrityCheckStep(site))
      .verification(buildTOCTOUTraceStep(site));

    const chain = cap(builder.build(), N12_CONFIDENCE_CAP);
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
    rationale: `N12 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new ResourceSubscriptionPoisoningRule());

export { ResourceSubscriptionPoisoningRule };
