/**
 * K13 — Unsanitized Tool Output (v2).
 *
 * Emits one finding per tool-response site that carries external content
 * without a sanitizer applied to the returned identifier. Zero regex;
 * confidence cap 0.90. Charter and edge-case strategy are specified in
 * `CHARTER.md`.
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
import { gatherK13, type UnsanitizedFlow } from "./gather.js";
import { stepInspectSource, stepInspectResponse, stepInspectSanitizer } from "./verification.js";

const RULE_ID = "K13";
const RULE_NAME = "Unsanitized Tool Output";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.90;

const REMEDIATION =
  "Tool responses must not carry raw external content to the AI client. " +
  "Acceptable mitigations: (1) apply a sanitizer — sanitize(), sanitizeHtml(), " +
  "escapeHtml(), DOMPurify.sanitize(), he.encode(), validator.escape(), " +
  "stripTags() — to the returned value BEFORE emission, (2) when returning " +
  "JSON, ensure every string field originating from external sources is " +
  "coerced to plain text and never rendered as HTML or Markdown by the " +
  "client, (3) attach a trust-boundary annotation that the client can use " +
  "to quarantine the content. CoSAI MCP-T4 and OWASP ASI02 treat " +
  "unsanitized tool output as a direct tool-poisoning substrate — the AI " +
  "interprets the response as a trustworthy tool result and gives external " +
  "content authority it never earned.";

const REF_COSAI_T4 = {
  id: "CoSAI-MCP-T4",
  title: "CoSAI MCP Security — T4 Data / Control Boundary Failure",
  url: "https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy",
  relevance:
    "CoSAI T4 specifies that tool outputs carrying untrusted external content " +
    "to the AI client without sanitization are a data/control boundary failure " +
    "by construction. The client is entitled to assume tool responses were " +
    "scrubbed at the server boundary.",
} as const;

class K13UnsanitizedToolOutputRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  // K13 uses a bespoke TypeScript-AST walker (gather.ts) that identifies
  // function-level external-source reads and response-emission sites, then
  // classifies the flow as sanitised or unsanitised within the enclosing
  // function. It does NOT route through `analyzeASTTaint` — the generic
  // taint engine's source vocabulary (req.body, process.env, readFileSync)
  // and sink vocabulary (exec, eval, SQL query) don't match K13's concept
  // of "external content reaching a return statement". Declaring
  // `ast-taint` was historically aspirational; the evidence-integrity
  // harness correctly rejects the claim because isReachable() asks the
  // taint engine to prove a flow the taint engine has no vocabulary for.
  // `structural` is the accurate label for this AST-walk analysis.
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK13(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const flow of file.flows) {
        if (flow.sanitizerApplied.sameVariable) continue;
        findings.push(this.buildFinding(flow));
      }
    }
    return findings.slice(0, 10);
  }

  private buildFinding(flow: UnsanitizedFlow): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: sourceTypeFor(flow.source.kind),
        location: flow.source.location,
        observed: flow.source.observed,
        rationale:
          `External-content read classified as \`${flow.source.kind}\`. ` +
          `Values returned by this call are outside the server's trust ` +
          `boundary — a web fetch may return attacker-controlled page ` +
          `content, a file read may return attacker-influenced bytes, a ` +
          `database row may carry content written by a different principal.`,
      })
      .propagation({
        propagation_type:
          flow.source.identifier !== null ? "variable-assignment" : "direct-pass",
        location: flow.responseLocation,
        observed:
          flow.source.identifier !== null
            ? `External value bound to \`${flow.source.identifier}\` then ` +
              `emitted via ${flow.siteType}.`
            : `External value flows directly through the expression tree ` +
              `into the ${flow.siteType} without an intermediate binding.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: flow.responseLocation,
        observed:
          `Tool response emits external content to the AI client via ` +
          `${flow.siteType}.`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: flow.sanitizerApplied.present,
        location: flow.enclosingFunctionLocation ?? flow.responseLocation,
        detail: flow.sanitizerApplied.detail,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `The AI client processes the tool response as a trustworthy ` +
          `statement of fact. If the external source was attacker- ` +
          `controlled (web scrape of a hostile page, file read of a path ` +
          `the attacker can influence, DB row written by an untrusted ` +
          `principal), the injection payload reaches the model at the ` +
          `tool-output boundary without any intermediate control. This ` +
          `is the indirect-injection archetype (Rehberger 2024, Invariant ` +
          `Labs 2025).`,
      })
      .factor(
        `external_source_${flow.source.kind.split("-").join("_")}`,
        sourceWeight(flow.source.kind),
        `External source classified as \`${flow.source.kind}\`.`,
      )
      .factor(
        "no_sanitizer_on_returned_value",
        flow.sanitizerApplied.present ? 0.04 : 0.10,
        flow.sanitizerApplied.present
          ? `A sanitizer was observed in scope but does not operate on the ` +
            `returned identifier — the compliance gap stands.`
          : `No sanitizer observed in the enclosing function body.`,
      );

    builder.reference(REF_COSAI_T4);
    builder.verification(stepInspectSource(flow));
    builder.verification(stepInspectResponse(flow));
    builder.verification(stepInspectSanitizer(flow));

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

function sourceTypeFor(kind: UnsanitizedFlow["source"]["kind"]):
  | "external-content"
  | "file-content"
  | "database-content"
  | "user-parameter" {
  switch (kind) {
    case "network-fetch":
    case "external-scrape":
      return "external-content";
    case "file-read":
      return "file-content";
    case "db-query":
      return "database-content";
    case "handler-param":
      return "user-parameter";
  }
}

function sourceWeight(kind: UnsanitizedFlow["source"]["kind"]): number {
  switch (kind) {
    case "network-fetch":
    case "external-scrape":
      return 0.12;
    case "db-query":
      return 0.10;
    case "file-read":
      return 0.08;
    case "handler-param":
      return 0.07;
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K13 charter caps confidence at ${cap} — a runtime sanitizer layered ` +
      `between this handler and the client (Express middleware, reverse ` +
      `proxy response transform, SDK-level content filter) is not visible ` +
      `at file scope.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K13UnsanitizedToolOutputRule());

export { K13UnsanitizedToolOutputRule };
