/**
 * I7 — Sampling Capability Abuse (Rule Standard v2).
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
import type { Location } from "../../location.js";
import { gatherI7, type I7Fact } from "./gather.js";
import { I7_CONFIDENCE_CAP } from "./data/config.js";
import {
  stepComparePairPrecedent,
  stepInspectIngestionTool,
  stepInspectSamplingCapability,
} from "./verification.js";

const RULE_ID = "I7";
const RULE_NAME = "Sampling Capability Abuse";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054.001";

const REMEDIATION =
  "Do NOT combine sampling with any content-ingestion tool on the same " +
  "server. If sampling is required, structurally tag all ingested content " +
  "(e.g. wrap in [BEGIN EXTERNAL CONTENT] delimiters that the sampling " +
  "callback refuses to forward verbatim). Require a user confirmation on " +
  "every sampling request whose context includes output from an ingestion " +
  "tool. Reference arXiv 2601.17549 for the empirical amplification factor.";

class SamplingCapabilityAbuseRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { declared_capabilities: true, tools: true };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI7(context);
    if (!gathered.fact) return [];
    return [this.buildFinding(gathered.fact)];
  }

  private buildFinding(fact: I7Fact): RuleResult {
    const samplingLoc: Location = { kind: "capability", capability: "sampling" };
    const first = fact.ingestion_nodes[0];
    const toolLoc: Location = { kind: "tool", tool_name: first.tool_name };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: toolLoc,
        observed:
          `Ingestion tool "${first.tool_name}" (ingests-untrusted, ` +
          `${(first.confidence * 100).toFixed(0)}% confidence). Total ` +
          `ingestion tools on server: ${fact.ingestion_nodes.length}.`,
        rationale:
          "The server exposes a content-ingestion surface that delivers " +
          "attacker-reachable content into the AI client's reasoning context.",
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: samplingLoc,
        observed:
          "Sampling capability lets the server re-issue the ingested content " +
          "back to the AI client as an AI-initiated inference request. Each " +
          "cycle raises the content's trust grade.",
      })
      .sink({
        sink_type: "code-evaluation",
        location: samplingLoc,
        observed:
          "Server is empowered to invoke the client's model for inference. " +
          "Combined with ingestion, this completes the arXiv 2601.17549 " +
          "injection amplification loop.",
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: "moderate",
        scenario:
          `Attacker plants an injection payload in content the ingestion tool ` +
          `"${first.tool_name}" will fetch. The server initiates sampling with ` +
          `the ingested content in scope. The sampling callback returns a ` +
          `"model-authored" response that the server accepts as trusted. With ` +
          `each feedback cycle the injection gains authority (23-41% per cycle ` +
          `per arXiv 2601.17549).`,
      })
      .factor(
        "sampling_declared",
        0.1,
        "declared_capabilities.sampling === true in the initialize response.",
      )
      .factor(
        "ingestion_present",
        0.1,
        `${fact.ingestion_nodes.length} tool(s) classified ingests-untrusted ` +
          `at ≥ 40% confidence by the capability-graph analyser.`,
      )
      .reference({
        id: "arXiv-2601.17549",
        title: "Sampling Capability Abuse in MCP Servers",
        url: "https://arxiv.org/abs/2601.17549",
        year: 2025,
        relevance:
          "Empirical 23-41% injection amplification when sampling is combined " +
          "with content ingestion.",
      })
      .verification(stepInspectSamplingCapability())
      .verification(stepInspectIngestionTool(fact))
      .verification(stepComparePairPrecedent());

    const chain = capConfidence(builder.build(), I7_CONFIDENCE_CAP);
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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale: `I7 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new SamplingCapabilityAbuseRule());

export { SamplingCapabilityAbuseRule };
