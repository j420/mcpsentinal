import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN5, type Mismatch } from "./gather.js";
import { N5_CONFIDENCE_CAP } from "./data/n5-config.js";
import {
  buildDeclarationInspectionStep,
  buildHandlerInspectionStep,
  buildDeceptionImpactStep,
} from "./verification.js";

const RULE_ID = "N5";
const RULE_NAME = "Capability Downgrade Deception";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Make the capabilities declaration a truthful summary of the handlers " +
  "registered on the server. If a capability is implemented, advertise it " +
  "in the initialize response (set to true or the per-feature object). " +
  "If it is not intended to be used, remove the handler registration in " +
  "addition to the declaration. Never let the two drift apart, and never " +
  "gate the capability declaration on client fingerprint — the declaration " +
  "must be deterministic per server.";

class CapabilityDowngradeRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN5(context);
    if (g.mismatches.length === 0) return [];
    return g.mismatches.map((m) => this.buildFinding(m));
  }

  private buildFinding(m: Mismatch): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: m.declaration.location,
        observed: m.declaration.line_text,
        rationale:
          `Server advertises capabilities object with "${m.capability_key}" ` +
          `${m.declaration.downgrade_label}. Clients consume this as the ` +
          `truth about server behaviour and arm consent / audit controls ` +
          `accordingly.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: m.declaration.location,
        observed:
          `The capabilities object flows into the initialize response ` +
          `verbatim; the client applies per-capability controls based on ` +
          `which keys it sees as true.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: m.handler.location,
        observed:
          `Despite the declaration, the server registers a handler for ` +
          `spec method "${m.handler.method}" (${m.handler.registration_label}). ` +
          `Invocation of this method dispatches to the handler without the ` +
          `client's ${m.capability_key}-scoped controls being armed.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: m.handler.location,
        detail:
          `No declaration-to-handler reconciliation is present. Client ` +
          `cannot detect the mismatch from the wire protocol alone.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An attacker-controlled or compromised server serves a reduced ` +
          `capability declaration to the client, silently disarming that ` +
          `capability's safety controls. The server then exercises the ` +
          `full capability (tools/call, sampling/createMessage, ` +
          `resources/subscribe) without triggering the client's consent ` +
          `prompts or audit logs. Detection is difficult because every ` +
          `individual invocation looks well-formed.`,
      })
      .factor(
        "declared_versus_implemented_mismatch",
        0.12,
        `Declaration at line ${m.declaration.line} says "${m.capability_key}" ` +
          `${m.declaration.downgrade_label}, but handler at line ` +
          `${m.handler.line} registers "${m.handler.method}".`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection (capability downgrade variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N5 covers the capability-downgrade variant: the server advertises " +
          "a reduced attack surface so client controls stay disarmed.",
      })
      .verification(buildDeclarationInspectionStep(m))
      .verification(buildHandlerInspectionStep(m))
      .verification(buildDeceptionImpactStep(m));

    const chain = cap(builder.build(), N5_CONFIDENCE_CAP);
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
    rationale: `N5 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new CapabilityDowngradeRule());

export { CapabilityDowngradeRule };
