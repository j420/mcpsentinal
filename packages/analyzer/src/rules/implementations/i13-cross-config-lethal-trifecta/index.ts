/**
 * I13 — Cross-Config Lethal Trifecta (Rule Standard v2).
 *
 * Detects the three-leg lethal trifecta distributed across MULTIPLE MCP
 * servers in the same client configuration. F1 fires when a single
 * server has all three legs; I13 fires when the three legs are
 * distributed across ≥2 servers, with the AI client bridging them.
 *
 * CRITICAL: I13 findings MUST carry rule_id "I13" as a literal string.
 * packages/scorer/src/scorer.ts applies the 40-point score cap via
 * `finding.rule_id === "F1" || finding.rule_id === "I13"`. Any rename
 * or mangling silently breaks the cap, which is the rule's entire
 * reason for existing.
 *
 * Confidence cap: 0.90 (same ceiling as F1 — capability-graph
 * detection is structurally deterministic). See CHARTER "Why
 * confidence is capped at 0.90" for the 0.05-below-ceiling reasoning.
 *
 * Honest-refusal rule: I13 requires the scanner to attach a
 * `multi_server_tools` extension to the AnalysisContext (or ≥2
 * servers inside it). Per-server scans (the common case) return [].
 *
 * No regex literals. No string-literal arrays > 5. Leg vocabulary in
 * ./data/capability-legs.ts as typed Records.
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
import {
  gatherI13,
  type I13Gathered,
  type ServerContribution,
} from "./gather.js";
import {
  stepCheckClientIsolation,
  stepInspectLeg,
  stepTraceCrossServerFlow,
} from "./verification.js";
import { I13_CONFIDENCE_CAP } from "./data/capability-legs.js";

// LITERAL "I13" — scorer.ts:254,269 key on this exact string. Do not mangle.
const RULE_ID = "I13";
const RULE_NAME = "Cross-Config Lethal Trifecta";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "The MCP client configuration combines servers whose capabilities together form the " +
  "lethal trifecta (private data + untrusted content + external communication), " +
  "distributed across multiple servers. No single server triggers F1, but the combination " +
  "enables cross-server data exfiltration bridged by the AI client. Options: (a) remove " +
  "one of the three legs from the configuration — drop the private-data server, the " +
  "untrusted-content server, or the external-comms server; (b) split the configuration " +
  "so the three legs never share a session; (c) add a destination allowlist to every " +
  "external-comms tool. Until mitigated, MCP Sentinel caps the total score at 40.";

class CrossConfigLethalTrifectaRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI13(context);
    if (!gathered.applicable || !gathered.trifecta_present) return [];
    return [this.buildFinding(gathered)];
  }

  private buildFinding(g: I13Gathered): RuleResult {
    // Pick the highest-confidence representative contribution for each leg as
    // the primary link targets.
    const pdLead = pickLead(g.legs.private_data);
    const utLead = pickLead(g.legs.untrusted_content);
    const exLead = pickLead(g.legs.external_comms);

    const serversInvolved = g.contributions.length;
    const serverSummary = g.contributions
      .map(
        (c) =>
          `${c.server_name} → [${c.legs.join(", ")}] via tools [${c.tool_names.join(", ")}]`,
      )
      .join("; ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: pdLead.location,
        observed:
          `Private-data leg on server "${pdLead.server_name}" — tool "${pdLead.tool_name}" ` +
          `(${pdLead.capability}, confidence ${(pdLead.confidence * 100).toFixed(0)}%).`,
        rationale:
          `The MCP client configuration contains ${serversInvolved} servers whose ` +
          `combined capability surface forms the lethal trifecta. No single server has ` +
          `all three legs; the AI client bridges them by routing outputs between tools ` +
          `of different servers within the same session. Simon Willison (2025) ` +
          `identified this structural pattern as one no prompt-level defence can close.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: utLead.location,
        observed:
          `Untrusted-content leg on server "${utLead.server_name}" — tool ` +
          `"${utLead.tool_name}" (${utLead.capability}). Distribution: ${serverSummary}.`,
      })
      .sink({
        sink_type: "network-send",
        location: exLead.location,
        observed:
          `External-comms leg on server "${exLead.server_name}" — tool ` +
          `"${exLead.tool_name}" (${exLead.capability}). Data read by the private-data ` +
          `leg can be exfiltrated through this tool after an injection payload arrives ` +
          `via the untrusted-content leg.`,
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: false,
        location: { kind: "capability", capability: "tools" },
        detail:
          "No MCP client today provides cross-server isolation. All tools from all " +
          "configured servers are in the same session with no trust boundary between " +
          "them. The mitigation is inherently absent at the client level; it must be " +
          "enforced by the configuration (server removal or allowlist) instead.",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `An attacker poisons the untrusted-content leg (e.g. a webpage scraped by ` +
          `"${utLead.tool_name}" or an email read by a similar tool). The injection ` +
          `instructs the AI to call "${pdLead.tool_name}" to retrieve private data, ` +
          `then call "${exLead.tool_name}" to send it outside the trust boundary. No ` +
          `individual tool is dangerous alone; the three legs compose into a complete ` +
          `exfiltration chain bridged by the AI client. MCP Sentinel caps this ` +
          `configuration's total score at 40.`,
      })
      .factor(
        "distributed_trifecta",
        0.1,
        `Lethal trifecta distributed across ${serversInvolved} servers in the same ` +
          `client config. Single-server F1 misses this; I13 detects the composed shape. ` +
          `Distribution: ${serverSummary}.`,
      )
      .factor(
        "graph_confirmed",
        0.08,
        `Merged capability graph (${g.graph.nodes.length} nodes) independently ` +
          `confirms all three legs with min-leg confidence ` +
          `${(g.min_leg_confidence * 100).toFixed(0)}%.`,
      )
      .factor(
        "cross_server_bridging",
        0.06,
        `The AI client bridges ${serversInvolved} servers without any isolation — no ` +
          `MCP client today enforces per-server trust boundaries.`,
      );

    builder.reference({
      id: "Willison-Lethal-Trifecta-2025",
      title: "The Lethal Trifecta — Simon Willison (2025)",
      url: "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",
      year: 2025,
      relevance:
        "Willison's 2025 formulation of the three-leg structural risk pattern. I13 " +
        "extends the pattern across server boundaries — the same three legs, distributed " +
        "through an AI client that has no cross-server isolation.",
    });

    // Verification steps — one per leg + a cross-server flow trace + config check.
    builder.verification(stepInspectLeg("private-data", pdLead));
    builder.verification(stepInspectLeg("untrusted-content", utLead));
    builder.verification(stepInspectLeg("external-comms", exLead));
    builder.verification(stepTraceCrossServerFlow(g.contributions as ServerContribution[]));
    builder.verification(stepCheckClientIsolation(g.contributions as ServerContribution[]));

    const chain = capConfidence(builder.build(), I13_CONFIDENCE_CAP);

    return {
      // CRITICAL: literal "I13" — scorer.ts keys on this exact string for the 40-point cap.
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function pickLead<T extends { confidence: number }>(candidates: T[]): T {
  if (candidates.length === 0) {
    throw new Error("I13.buildFinding: no candidates for a leg that should exist");
  }
  let best = candidates[0];
  for (const c of candidates) {
    if (c.confidence > best.confidence) best = c;
  }
  return best;
}

/**
 * Clamp chain.confidence to cap and record the clamp as an auditable
 * ConfidenceFactor.
 */
function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `I13 charter caps confidence at ${cap}. The cross-server merged-graph analysis is ` +
      `deterministic, but the scanner cannot statically detect whether some servers ` +
      `failed to enumerate — the 0.05-below-ceiling gap preserves room for that.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new CrossConfigLethalTrifectaRule());

export { CrossConfigLethalTrifectaRule };
