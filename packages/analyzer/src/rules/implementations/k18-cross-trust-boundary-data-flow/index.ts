/**
 * K18 — Cross-Trust-Boundary Data Flow in Tool Response (v2).
 *
 * Emits one finding per tainted sensitive value that reaches a response /
 * network-send sink without a same-variable redactor. Zero regex;
 * confidence cap 0.88.
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
import { gatherK18, type CrossBoundaryFlow } from "./gather.js";
import {
  stepInspectSource,
  stepInspectSink,
  stepInspectRedactor,
} from "./verification.js";

const RULE_ID = "K18";
const RULE_NAME = "Cross-Trust-Boundary Data Flow in Tool Response";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0057" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Sensitive values (env secrets, credentials, private keys, classified " +
  "record fields) must not cross the trust boundary from the server into " +
  "the AI client's context window or an outbound network request without " +
  "a classification-aware redaction step. Acceptable mitigations: (1) apply " +
  "a redactor to the tainted value BEFORE the response — redact() / mask() " +
  "/ strip() / omit() / scrub() — and confirm the redactor's argument is " +
  "the SAME identifier that reaches the sink, (2) avoid returning the " +
  "secret entirely and return a boolean / opaque identifier instead, (3) " +
  "route the secret through an encrypted channel where the client holds a " +
  "key the server cannot read. CoSAI MCP-T5, ISO 27001 A.5.14, and EU AI " +
  "Act Article 15 treat the unredacted boundary crossing as an auditable " +
  "control gap regardless of whether a specific request, at this moment, " +
  "has leaked a specific secret.";

const REF_COSAI_T5 = {
  id: "CoSAI-MCP-T5",
  title: "CoSAI MCP Security — T5 Inadequate Data Protection",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "T5 requires a classification-aware redaction step on every cross- " +
    "trust-boundary transfer. A tool response carrying an env secret or " +
    "credential without redaction is a T5 control gap.",
} as const;

class K18CrossTrustBoundaryDataFlowRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK18(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const flow of file.flows) {
        if (flow.redactor.sameVariable) continue;
        findings.push(this.buildFinding(flow));
      }
    }
    return findings.slice(0, 10);
  }

  private buildFinding(flow: CrossBoundaryFlow): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: sourceTypeFor(flow.source.kind),
        location: flow.source.location,
        observed: flow.source.observed,
        rationale:
          `Sensitive value classified as \`${flow.source.kind}\`. ` +
          (flow.source.kind === "env-secret"
            ? `Environment variable whose name matches sensitivity suffix tokens.`
            : flow.source.kind === "credential-call"
              ? `CallExpression routed through a credential store or whose method name is a credential vocabulary term.`
              : flow.source.kind === "sensitive-path"
                ? `File read targeting a known sensitive system path literal.`
                : `Function parameter whose name includes a sensitivity token (softer evidence).`),
      })
      .propagation({
        propagation_type:
          flow.source.identifier !== null ? "variable-assignment" : "direct-pass",
        location: flow.sinkLocation,
        observed:
          flow.source.identifier !== null
            ? `Sensitive value bound to \`${flow.source.identifier}\` then ` +
              `emitted via ${flow.sinkKind}.`
            : `Sensitive value flows through the expression tree directly ` +
              `into the ${flow.sinkKind}.`,
      })
      .sink({
        sink_type:
          flow.sinkKind === "network-send" ? "network-send" : "credential-exposure",
        location: flow.sinkLocation,
        observed: `${flow.sinkKind} carries sensitive content across trust boundary`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: flow.redactor.present,
        location: flow.enclosingFunctionLocation ?? flow.sinkLocation,
        detail: flow.redactor.detail,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: flow.sinkKind === "network-send" ? "connected-services" : "ai-client",
        exploitability: "moderate",
        scenario:
          flow.sinkKind === "network-send"
            ? `The secret leaves the server in an outbound HTTP request body, ` +
              `reaching a third-party endpoint outside the organisation's ` +
              `trust zone. Any log / SIEM / network inspector along the path ` +
              `retains it; OWASP LLM06 names the class.`
            : `The LLM receives the secret in its context window, may echo ` +
              `it in subsequent turns, and every downstream log / tool ` +
              `capturing the response exposes the value at its own layer. ` +
              `OWASP LLM06 names this the archetypal disclosure pattern.`,
      })
      .factor(
        `sensitive_source_${flow.source.kind.split("-").join("_")}`,
        sourceWeight(flow.source.kind),
        `Sensitive source classified as \`${flow.source.kind}\`.`,
      )
      .factor(
        "external_sink_reached",
        sinkWeight(flow.sinkKind),
        `Tainted value reaches ${flow.sinkKind} — a cross-trust-boundary ` +
          `transfer.`,
      )
      .factor(
        "no_redactor_on_tainted_value",
        flow.redactor.present ? 0.03 : 0.10,
        flow.redactor.present
          ? `Redactor observed in scope but does NOT operate on the tainted ` +
            `identifier — the compliance gap stands.`
          : `No redactor observed in the enclosing function body.`,
      );

    if (flow.paramNameOnly) {
      builder.factor(
        "param_name_only_sensitivity",
        -0.10,
        `Sensitivity classification rests entirely on a parameter-name ` +
          `heuristic; the actual value may already be hashed / opaque. ` +
          `Confidence is down-weighted per charter.`,
      );
    }

    builder.reference(REF_COSAI_T5);
    builder.verification(stepInspectSource(flow));
    builder.verification(stepInspectSink(flow));
    builder.verification(stepInspectRedactor(flow));

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

function sourceTypeFor(kind: CrossBoundaryFlow["source"]["kind"]):
  | "environment"
  | "file-content"
  | "user-parameter"
  | "external-content" {
  switch (kind) {
    case "env-secret":
      return "environment";
    case "credential-call":
      return "external-content";
    case "sensitive-path":
      return "file-content";
    case "sensitive-param":
      return "user-parameter";
  }
}

function sourceWeight(kind: CrossBoundaryFlow["source"]["kind"]): number {
  switch (kind) {
    case "env-secret":
    case "credential-call":
      return 0.15;
    case "sensitive-path":
      return 0.12;
    case "sensitive-param":
      return 0.07;
  }
}

function sinkWeight(kind: CrossBoundaryFlow["sinkKind"]): number {
  switch (kind) {
    case "network-send":
      return 0.12;
    case "response-call":
    case "return-statement":
      return 0.10;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K18 charter caps confidence at ${cap} — middleware-based redactors ` +
      `and cross-module flows are invisible to a file-scope walker. A ` +
      `maximum-confidence claim would overstate what static evidence ` +
      `supports.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K18CrossTrustBoundaryDataFlowRule());

export { K18CrossTrustBoundaryDataFlowRule };
