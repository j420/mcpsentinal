/**
 * K15 — Multi-Agent Collusion Preconditions (v2).
 *
 * Emits one finding per write-surface / read-surface tool PAIR on the same
 * server that shares a shared-state surface AND lacks a trust-boundary
 * attestation on the write side. Zero regex; confidence cap 0.85.
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
import { gatherK15, type ColludingPair } from "./gather.js";
import {
  stepInspectWriteTool,
  stepInspectReadTool,
  stepInspectMitigation,
} from "./verification.js";

const RULE_ID = "K15";
const RULE_NAME = "Multi-Agent Collusion Preconditions";
const OWASP = "MCP05-privilege-escalation" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Every tool that writes to a multi-agent shared-state surface (memory, " +
  "scratchpad, vector store, session state, cross-agent pool) must declare " +
  "a machine-readable trust-boundary attestation. Three acceptable forms: " +
  "(1) set the tool annotation `trustBoundary` to an identifier naming the " +
  "isolation scope (per-agent, per-tenant), (2) add a REQUIRED parameter " +
  "carrying the actor identity (`agent_id`, `tenant_id`, `session_id`, " +
  "`namespace`) that the handler scopes the write against, (3) encode " +
  "isolation in the tool NAME (`isolated_write`, `scoped_put`, " +
  "`per_agent_set`). Without one of these, a downstream agent reading the " +
  "same surface cannot distinguish trusted from attacker-injected content. " +
  "MAESTRO L7 and CoSAI MCP-T9 require the attestation even when no " +
  "runtime collusion has been observed.";

const REF_MAESTRO_L7 = {
  id: "MAESTRO-L7",
  title: "MAESTRO — Layer 7 Agent Ecosystem",
  url: "https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling",
  relevance:
    "L7 names inter-agent collusion via unattested shared state as the " +
    "archetypal agent-ecosystem threat. K15 detects the static precondition: " +
    "a write tool paired with a read tool on the same shared surface, without " +
    "a machine-readable trust-boundary attestation.",
} as const;

class K15MultiAgentCollusionPreconditionsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true, min_tools: 2 };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK15(context);
    const findings: RuleResult[] = [];
    for (const pair of gathered.pairs) {
      if (pair.mitigated) continue;
      findings.push(this.buildFinding(pair));
    }
    return findings.slice(0, 10);
  }

  private buildFinding(pair: ColludingPair): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "agent-output",
        location: pair.writeTool.toolLocation,
        observed:
          `tool \`${pair.writeTool.toolName}\` writes to shared-state ` +
          `surface (${pair.surfaceTokens.join(", ")})`,
        rationale:
          `Write-surface tool \`${pair.writeTool.toolName}\` targets a ` +
          `shared-state surface named by tokens \`${pair.surfaceTokens.join(
            ", ",
          )}\`. Any MCP client wiring this server to multiple agents gives ` +
          `the writer an authority it cannot attest: the downstream reader ` +
          `treats content as if it were from a trusted source.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: pair.readTool.toolLocation,
        observed:
          `tool \`${pair.readTool.toolName}\` reads the same surface ` +
          `(${pair.surfaceTokens.join(", ")})`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: pair.readTool.toolLocation,
        observed:
          `Read-surface tool emits shared-state content to the AI client ` +
          `without any provenance signal.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: pair.writeTool.toolLocation,
        detail: pair.mitigationDetail,
      })
      .impact({
        impact_type: "cross-agent-propagation",
        scope: "other-agents",
        exploitability: "moderate",
        scenario:
          `A compromised upstream agent invokes \`${pair.writeTool.toolName}\` ` +
          `to insert poisoned content into the shared surface. A downstream ` +
          `agent invokes \`${pair.readTool.toolName}\` and acts on the ` +
          `content as if it were authoritative. Invariant Labs (Jan 2026) ` +
          `demonstrated the pattern with vector stores; Rehberger (Nov 2025) ` +
          `demonstrated it with AutoGen scratchpads. Neither attack required ` +
          `privilege escalation in the MCP protocol itself — only an ` +
          `unattested write surface.`,
      })
      .factor(
        "shared_write_tool",
        0.09,
        `Write-side tool \`${pair.writeTool.toolName}\` classified by ` +
          `shared-state tokens \`${pair.writeTool.sharedStateTokens.join(", ")}\`.`,
      )
      .factor(
        "corresponding_read_tool",
        0.08,
        `Read-side tool \`${pair.readTool.toolName}\` classified by ` +
          `shared-state tokens \`${pair.readTool.sharedStateTokens.join(", ")}\`.`,
      )
      .factor(
        "no_trust_boundary_attestation",
        0.10,
        `No trustBoundary annotation, required agent-identity parameter, or ` +
          `isolation-scoped name token on the write side.`,
      );

    // Down-weight when matches are description-only (linguistic heuristic).
    if (pair.writeTool.matchMode === "description" && pair.readTool.matchMode === "description") {
      builder.factor(
        "linguistic_only_classification",
        -0.10,
        `Both tools are classified via description tokens, not name tokens. ` +
          `The linguistic match is softer evidence than a machine-readable ` +
          `capability signal — confidence is reduced accordingly.`,
      );
    }

    builder.reference(REF_MAESTRO_L7);
    builder.verification(stepInspectWriteTool(pair));
    builder.verification(stepInspectReadTool(pair));
    builder.verification(stepInspectMitigation(pair));

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K15 charter caps confidence at ${cap} — runtime collusion behaviour is ` +
      `invisible to static analysis, and the machine-readable attestation ` +
      `signals the rule requires are not yet standardised in the MCP ` +
      `protocol. A maximum-confidence claim would overstate what static ` +
      `evidence supports.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new K15MultiAgentCollusionPreconditionsRule());

export { K15MultiAgentCollusionPreconditionsRule };
