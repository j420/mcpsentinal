/**
 * N7 — Progress Token Prediction and Injection (Rule Standard v2).
 *
 * Aligns with rules/N7-progress-token-abuse.yaml (the previous N3 class in
 * jsonrpc-protocol-v2.ts covered part of this concern under the wrong id).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import type { Location } from "../../location.js";
import { gather, type ProgressTokenFact } from "./gather.js";
import {
  verifyTokenSource,
  verifyNoOwnershipValidation,
  verifyNotificationsEmit,
  toLocation,
} from "./verification.js";

const RULE_ID = "N7";
const RULE_NAME = "Progress Token Prediction and Injection";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.88;

const REMEDIATION =
  "Generate progressToken server-side with crypto.randomUUID() (or equivalent). " +
  "Bind each token to the session/request that caused the long-running operation " +
  "and verify ownership before accepting any notifications/progress emission that " +
  "references it. Never accept progressToken directly from request params without " +
  "rebinding. MCP spec 2025-03-26 §5.1 leaves this to the server — the SDK does not " +
  "enforce it.";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N7ProgressTokenAbuse implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const { facts } = gather(context.source_code);
    if (facts.length === 0) return [];

    return [this.buildFinding(facts[0])];
  }

  private buildFinding(fact: ProgressTokenFact): RuleResult {
    const b = new EvidenceChainBuilder();
    const loc: Location = toLocation(fact.location);

    const sourceType = fact.source_kind === "user-input" ? "user-parameter" : "file-content";

    b.source({
      source_type: sourceType,
      location: loc,
      observed: fact.location.snippet,
      rationale:
        fact.source_kind === "user-input"
          ? `Progress token ${fact.target_identifier} assigned directly from user-controlled input ` +
            `(${fact.rhs_expression}). The server never rebinds to a cryptographic random value.`
          : `Progress token ${fact.target_identifier} generated from a predictable server-local source ` +
            `(${fact.rhs_expression}, ${fact.source_kind}). Enumeration is trivial.`,
    });

    b.propagation({
      propagation_type: fact.source_kind === "user-input" ? "direct-pass" : "variable-assignment",
      location: loc,
      observed:
        `Token value ${fact.rhs_expression} assigned to ${fact.target_identifier} and ` +
        `subsequently used as the correlation key for notifications/progress emissions.`,
    });

    b.sink({
      sink_type: "config-modification",
      location: loc,
      observed:
        `Untrusted/predictable token reaches the progress-correlation field that drives ` +
        `notifications/progress dispatch.`,
    });

    b.impact({
      impact_type: fact.source_kind === "user-input" ? "session-hijack" : "denial-of-service",
      scope: "connected-services",
      exploitability: fact.source_kind === "user-input" ? "trivial" : "moderate",
      scenario:
        fact.source_kind === "user-input"
          ? `Attacker controls the progress token; server emits notifications/progress for ` +
            `sessions other than the attacker's, enabling progress-spoof UI manipulation ` +
            `and cross-session signalling.`
          : `Attacker enumerates upcoming progress tokens; injects fake progress updates ` +
            `that appear to originate from legitimate long-running requests, stalling the ` +
            `client UI or triggering unwanted cancel flows.`,
    });

    const adjustment = fact.source_kind === "user-input" ? 0.16 : 0.09;
    b.factor(
      "weak_progress_token_source",
      adjustment,
      `AST-confirmed: ${fact.target_identifier} = ${fact.rhs_expression} (${fact.source_kind}); ` +
        `enclosing scope contains no cryptographic generator.`,
    );

    b.reference({
      id: "MCP-2025-03-26-progress",
      title: "MCP Specification 2025-03-26 — Progress Utility",
      url: "https://modelcontextprotocol.io/specification/2025-03-26/basic/utilities/progress",
      relevance:
        "Section 5.1 defines progressToken as opaque but does not mandate unpredictability or ownership validation.",
    });

    b.verification(verifyTokenSource(fact));
    b.verification(verifyNoOwnershipValidation(fact));
    b.verification(verifyNotificationsEmit(fact));

    const raw = b.build();
    const chain = { ...raw, confidence: Math.min(raw.confidence, CONFIDENCE_CEILING) };

    return {
      rule_id: RULE_ID,
      severity: SEVERITY,
      owasp_category: OWASP,
      mitre_technique: "AML.T0054",
      remediation: REMEDIATION,
      chain,
    };
  }
}

registerTypedRuleV2(new N7ProgressTokenAbuse());
