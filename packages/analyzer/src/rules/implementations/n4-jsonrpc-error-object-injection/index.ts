import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN4, type InjectSite } from "./gather.js";
import { N4_CONFIDENCE_CAP } from "./data/error-surfaces.js";
import {
  buildUserInputTraceStep,
  buildErrorPathTraceStep,
  buildSanitiserCheckStep,
} from "./verification.js";

const RULE_ID = "N4";
const RULE_NAME = "JSON-RPC Error Object Injection";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Never include user-controlled input verbatim in error.message or " +
  "error.data. Return generic error codes and descriptive templates " +
  "that do not echo the failing input. If input must be referenced, " +
  "run it through a dedicated error-path sanitiser that strips " +
  "LLM-significant bytes (control tokens, role markers, HTML/markdown " +
  "delimiters) before emission.";

class JSONRPCErrorInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN4(context);
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: InjectSite): RuleResult {
    const sanitised = site.sanitiser_distance !== null;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Line reads ${site.user_source.label} and places the content in ` +
          `${site.error_surface.label}. JSON-RPC error fields are displayed ` +
          `to the user and often forwarded into the agent's reasoning ` +
          `context by the client.`,
      })
      .propagation({
        propagation_type: "string-concatenation",
        location: site.location,
        observed:
          `User input is concatenated into / embedded in the error ` +
          `constructor on this line — the resulting Error's message / ` +
          `data flows through the JSON-RPC envelope to the client.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          `Client emits error.message / error.data into the agent's context ` +
          `without applying tool-description-level sanitisation — attacker ` +
          `bytes become prompt input.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: sanitised,
        location: site.location,
        detail: sanitised
          ? `Sanitiser "${site.sanitiser_label}" within window — confirm ` +
            `it actually applies to this error path.`
          : `No sanitiser within ±4 lines. Error path carries user bytes ` +
            `intact.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `An attacker crafts a request whose parameters contain a prompt-` +
          `injection payload, triggers an error condition, and the payload ` +
          `flows via error.message into the client's display and the ` +
          `agent's reasoning context. Unlike A1 (description injection), ` +
          `this bypasses tool-description sanitisers because the envelope ` +
          `is different.`,
      })
      .factor(
        "user_input_to_error_path",
        0.1,
        `Direct flow from ${site.user_source.label} to ${site.error_surface.label}.`,
      )
      .factor(
        sanitised ? "sanitiser_nearby" : "no_sanitiser",
        sanitised ? -0.2 : 0.05,
        sanitised
          ? `Sanitiser fragment nearby; confirm coverage.`
          : `No sanitiser within window — path is unsanitised.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — LLM Prompt Injection (error-envelope variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N4 detects the error-envelope variant of AML.T0054 where the " +
          "payload carrier is error.message / error.data rather than " +
          "tool.description.",
      })
      .verification(buildUserInputTraceStep(site))
      .verification(buildErrorPathTraceStep(site))
      .verification(buildSanitiserCheckStep(site));

    const chain = cap(builder.build(), N4_CONFIDENCE_CAP);
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
    rationale: `N4 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new JSONRPCErrorInjectionRule());

export { JSONRPCErrorInjectionRule };
