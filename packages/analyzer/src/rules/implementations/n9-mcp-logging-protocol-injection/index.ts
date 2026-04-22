import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN9, type LogInjectSite } from "./gather.js";
import { N9_CONFIDENCE_CAP } from "./data/log-surfaces.js";
import {
  buildLogFlowStep,
  buildNotificationTraceStep,
  buildSanitiserStep,
} from "./verification.js";

const RULE_ID = "N9";
const RULE_NAME = "MCP Logging Protocol Injection";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Treat notifications/message.data the same as tool response content: " +
  "sanitise LLM-significant bytes (control tokens, role markers, HTML / " +
  "markdown delimiters) before emission. Never put user-controlled " +
  "bytes in the `level` field. For server-side loggers that bridge into " +
  "the MCP notification channel, apply the sanitiser in the bridge layer " +
  "so every log entry is sanitised once, at a single choke point.";

class LoggingProtocolInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN9(context);
    if (g.sites.length === 0) return [];
    return g.sites.map((s) => this.buildFinding(s));
  }

  private buildFinding(site: LogInjectSite): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: site.location,
        observed: site.line_text,
        rationale:
          `Line reads ${site.user_input.label} and passes it to ` +
          `${site.log_surface.label}. Log channel content propagates ` +
          `into the client's audit trail and, for agentic clients, into ` +
          `the model's reasoning context.`,
      })
      .propagation({
        propagation_type: "string-concatenation",
        location: site.location,
        observed:
          `User input flows into the log channel; MCP notifications/message ` +
          `serialises the content on the wire with no further sanitisation.`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: site.location,
        observed:
          `Client-side forwarding of log content into agent context treats ` +
          `the attacker's bytes as prompt input.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: site.sanitised_nearby,
        location: site.location,
        detail: site.sanitised_nearby
          ? `Sanitiser fragment on the same line — confirm coverage.`
          : `No sanitiser on the line. User bytes pass through verbatim.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `Attacker issues a request whose parameters contain an injection ` +
          `payload. The server's log path echoes the payload into ` +
          `notifications/message; the client forwards the notification ` +
          `into the agent's context and into the audit store. The agent ` +
          `complies with the injection, and the audit log now shows a ` +
          `forged entry that masks the attack's origin.`,
      })
      .factor(
        "user_input_to_log_path",
        0.1,
        `Direct flow from ${site.user_input.label} to ${site.log_surface.label}.`,
      )
      .factor(
        site.sanitised_nearby ? "sanitiser_present" : "sanitiser_absent",
        site.sanitised_nearby ? -0.15 : 0.05,
        site.sanitised_nearby
          ? `Sanitiser present on line — confirm coverage.`
          : `Sanitiser absent — log path carries user bytes intact.`,
      )
      .reference({
        id: "MITRE-ATLAS-AML.T0054",
        title: "MITRE ATLAS AML.T0054 — Prompt Injection (log-envelope variant)",
        url: "https://atlas.mitre.org/techniques/AML.T0054",
        relevance:
          "N9 is the log-envelope variant: the carrier is notifications/" +
          "message rather than tool.description.",
      })
      .verification(buildLogFlowStep(site))
      .verification(buildNotificationTraceStep(site))
      .verification(buildSanitiserStep(site));

    const chain = cap(builder.build(), N9_CONFIDENCE_CAP);
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
    rationale: `N9 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new LoggingProtocolInjectionRule());

export { LoggingProtocolInjectionRule };
