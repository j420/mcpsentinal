import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherM9, type LeakSite } from "./gather.js";
import { M9_CONFIDENCE_CAP } from "./data/prompt-identifiers.js";
import {
  buildReadSiteStep,
  buildGateCheckStep,
  buildLeakImpactStep,
} from "./verification.js";

const RULE_ID = "M9";
const RULE_NAME = "Model-Specific System Prompt Extraction";
const OWASP = "ASI01-agent-goal-hijack" as const;
const MITRE = "AML.T0057";

const REMEDIATION =
  "Never return the agent's system prompt, initial instructions, or " +
  "system message through a tool response. Remove any debug path that " +
  "serialises the prompt. If diagnostic access is required, gate it " +
  "behind a separate admin-only endpoint that does NOT flow through " +
  "tools/call, and redact prompt content before emission.";

class SystemPromptExtractionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherM9(context);
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: LeakSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Code reads the ${site.prompt_ident.label} and flows it into a ` +
          `return-shaped construct (${site.return_fragment}). The system ` +
          `prompt IS the agent's safety posture — leaking it degrades every ` +
          `subsequent session's jailbreak resistance.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Prompt variable contents flow directly into the tool response ` +
          `payload without redaction.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: site.location,
        observed:
          `Response path exposes the system-prompt text to anyone with ` +
          `tool-invocation access, including attacker-controlled upstream ` +
          `agents or malicious downstream clients.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: site.gate_present,
        location: site.location,
        detail: site.gate_present
          ? `Gate "${site.gate_label}" found ${site.gate_distance} line(s) ` +
            `away — verify it actually guards this return path.`
          : `No dev / admin / debug gate within ±5 lines. Path is always ` +
            `reachable.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "ai-client",
        exploitability: "trivial",
        scenario:
          `Attacker invokes the tool once, reads the response, and extracts ` +
          `the full system prompt. Subsequent jailbreak attempts against ` +
          `this agent (and similarly-configured agents if prompts are ` +
          `reused across deployments) become dramatically easier because ` +
          `the attacker now knows the exact refusal phrases and safety rails.`,
      })
      .factor(
        "prompt_identifier_specificity",
        (site.prompt_ident.specificity - 0.5) * 0.2,
        `Observed identifier "${site.prompt_ident.fragment}" has ` +
          `specificity ${site.prompt_ident.specificity.toFixed(2)}; ` +
          `exact prompt-token names are higher-signal than generic ` +
          `"instructions".`,
      )
      .factor(
        site.gate_present ? "gate_possibly_present" : "no_gate_present",
        site.gate_present ? -0.2 : 0.05,
        site.gate_present
          ? `Gate keyword nearby; reviewer may confirm the path is ` +
            `dev-only.`
          : `No gate keyword — the return path is reachable in all ` +
            `deployment modes.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        url: "https://atlas.mitre.org/techniques/AML.T0057",
        relevance:
          "M9 detects the server-side enabler of AML.T0057 — code that " +
          "emits the system prompt via a tool response path.",
      })
      .verification(buildReadSiteStep(site))
      .verification(buildGateCheckStep(site))
      .verification(buildLeakImpactStep(site));

    const chain = cap(builder.build(), M9_CONFIDENCE_CAP);
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
    rationale: `M9 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new SystemPromptExtractionRule());

export { SystemPromptExtractionRule };
