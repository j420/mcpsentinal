/**
 * H3 — Multi-Agent Propagation Risk (v2)
 *
 * Orchestrator. Consumes the per-tool propagation-sink classifications
 * produced by `gather.ts` and emits v2 RuleResult[] with evidence
 * chains showing the inter-agent trust-boundary gap.
 *
 * Confidence cap: 0.75 per charter. Linguistic-signal inference
 * carries inherent ambiguity — the analyzer cannot observe the
 * actual trust boundaries a multi-agent architecture enforces at
 * runtime.
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
import { gatherH3, type H3Site } from "./gather.js";
import {
  stepInspectSink,
  stepCheckSanitization,
  stepReviewPropagationDoc,
} from "./verification.js";

const RULE_ID = "H3";
const RULE_NAME = "Multi-Agent Propagation Risk";
const OWASP = "ASI07-insecure-inter-agent-comms" as const;
const MITRE = "AML.T0059" as const;
const CONFIDENCE_CAP = 0.75;

const REMEDIATION =
  "Declare the trust boundary explicitly in the tool's description. For tools " +
  "that accept output from other agents, state whether the input is treated as " +
  "trusted or untrusted, and describe the sanitization the tool performs (input " +
  "validation, output encoding, or prompt-injection-aware escaping). For tools " +
  "that write to shared memory (vector stores, scratchpads, working-memory " +
  "files), declare the persistence scope and apply sanitization on write, not " +
  "on read — the first agent to write a poisoned memory can compromise every " +
  "downstream reader. Follow OWASP ASI07 guidance for inter-agent communication " +
  "boundaries and MITRE ATLAS AML.T0059 mitigations for shared-memory " +
  "manipulation.";

const REF_OWASP_ASI07 = {
  id: "OWASP-ASI07-Insecure-Inter-Agent-Comms",
  title: "OWASP Agentic Top 10 — ASI07 Insecure Inter-Agent Communications",
  url: "https://owasp.org/www-project-agentic-security-initiative/",
  relevance:
    "ASI07 names inter-agent communication without sanitization as a top-10 " +
    "agentic-architecture risk. H3 is MCP Sentinel's structural detector for " +
    "the tool-level surface of ASI07.",
} as const;

class MultiAgentPropagationRiskRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherH3(context);
    return gathered.sites.map((site) => this.buildFinding(site));
  }

  private buildFinding(site: H3Site): RuleResult {
    const primaryLocation = site.parameterLocation ?? site.toolLocation;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "agent-output",
        location: primaryLocation,
        observed: site.observed,
        rationale: site.entry.rationale,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: site.capabilityLocation,
        observed:
          site.sinkKind === "agent-input"
            ? `Tool "${site.toolName}" accepts output from another agent via ` +
              `the "${site.matchedToken}" signal. The tool does not declare a ` +
              `trust boundary in its description.`
            : `Tool "${site.toolName}" writes to a shared-memory surface ` +
              `(${site.matchedToken}) that other agents can read. Without ` +
              `sanitization on write, a compromised upstream agent poisons ` +
              `the memory for every downstream reader.`,
      })
      .sink({
        sink_type: "config-modification",
        location: primaryLocation,
        observed:
          site.sinkKind === "agent-input"
            ? `Compromised upstream agent output flows through this tool into ` +
              `the downstream agent's context under the downstream agent's ` +
              `authority.`
            : `Poisoned memory persists across sessions. Every downstream agent ` +
              `that reads the shared surface inherits the injection.`,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "other-agents",
        exploitability: site.dualRole ? "trivial" : "moderate",
        scenario:
          site.sinkKind === "agent-input"
            ? `A prompt injection in an upstream agent (via indirect injection, ` +
              `tool poisoning, or adversarial input) propagates through this ` +
              `tool into the downstream agent. The downstream agent executes the ` +
              `injected instructions under its own authority — the canonical ` +
              `multi-agent-cascade attack (Embrace The Red, November 2025).`
            : `A compromised upstream agent writes an attacker-authored string ` +
              `into the shared-memory surface. Every subsequent session that ` +
              `queries that memory (vector-store retrieval, scratchpad read, ` +
              `working-memory load) inherits the injection. Attack persistence ` +
              `is cross-session — the cross-agent-memory-pollution vector ` +
              `documented by Invariant Labs in January 2026.`,
      });

    addPropagationSinkFactor(builder, site);
    if (site.dualRole) {
      builder.factor(
        "dual_role_amplifier",
        0.08,
        "Tool matched BOTH agent-input and shared-memory-writer surfaces. A tool " +
          "that accepts agent output AND writes it to shared memory is the ideal " +
          "propagation amplifier — every downstream agent that reads the memory " +
          "inherits the injection from every upstream agent that wrote to it.",
      );
    }
    builder.factor(
      "sanitization_absence",
      site.sanitizationDeclared ? -0.2 : 0.04,
      site.sanitizationDeclared
        ? `Tool description declares a sanitization / trust-boundary signal. ` +
          `This should suppress the finding at the gather layer — the presence ` +
          `here indicates the signal was insufficient (e.g. present on the ` +
          `description but not on the flagged parameter).`
        : `Tool description contains no sanitization / trust-boundary signal. ` +
          `Confirms the trust-boundary declaration gap the rule detects.`,
    );

    builder.reference(REF_OWASP_ASI07);
    builder.verification(stepInspectSink(site));
    builder.verification(stepCheckSanitization(site));
    builder.verification(stepReviewPropagationDoc(site));

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

function addPropagationSinkFactor(
  builder: EvidenceChainBuilder,
  site: H3Site,
): void {
  builder.factor(
    "propagation_sink_class",
    site.entry.propagation_risk === "high" ? 0.08 : 0.02,
    `Classifier: ${site.sinkKind}. Token: "${site.matchedToken}". ${site.entry.rationale}`,
  );
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `H3 charter caps confidence at ${cap} — linguistic-signal inference on ` +
      `tool metadata carries inherent ambiguity. The rule cannot observe the ` +
      `actual trust-boundary enforcement at the architecture layer. The 0.25 ` +
      `gap preserves room for reviewer judgement.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MultiAgentPropagationRiskRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { MultiAgentPropagationRiskRule };
