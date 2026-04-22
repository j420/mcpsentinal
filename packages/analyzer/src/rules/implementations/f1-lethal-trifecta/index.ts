/**
 * F1 — Lethal Trifecta (Rule Standard v2).
 *
 * Signature detection of MCP Sentinel: three capability legs (private data,
 * untrusted content, external communication) coexisting on a single server's
 * capability surface. F1 is the canonical scorer-side "cap the score at 40"
 * signal — see `packages/scorer/src/scorer.ts`, which keys the cap on
 * `finding.rule_id === "F1"`.
 *
 * F1 also emits COMPANION findings under three partner rule ids (F2, F3, F6)
 * when the same graph pass surfaces:
 *   - command-injection chain / unrestricted-access → F2
 *   - credential-exposure path                     → F3
 *   - circular data loop (writes-data + reads-data cycle) → F6
 *
 * F2 / F3 / F6 have their own v2 directories with stub TypedRuleV2s that
 * return `[]`; the engine-level registration keeps the dispatcher quiet,
 * while F1 is the single producer of the findings. This is documented in
 * agent_docs/detection-rules.md §"Companion Rule Pattern".
 *
 * Inputs: the shared `capability-graph.ts` and `schema-inference.ts`
 * analyzers. Zero regex literals, zero string-literal arrays > 5. All
 * vocabulary lives in `./data/capability-legs.ts` as typed records.
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
import {
  gatherF1,
  type CompanionPattern,
  type F1Gathered,
  type LegContribution,
} from "./gather.js";
import {
  F1_CONFIDENCE_CAP,
} from "./data/capability-legs.js";
import {
  stepTraceCrossToolFlow,
  stepVerifyCompanion,
  stepVerifyExternalCommsLeg,
  stepVerifyPrivateDataLeg,
  stepVerifyUntrustedLeg,
} from "./verification.js";

const RULE_ID = "F1";
const RULE_NAME = "Lethal Trifecta";
const OWASP = "MCP04-data-exfiltration" as const;
const MITRE = "AML.T0054";

const F1_REMEDIATION =
  "This server presents the 'lethal trifecta' (Willison 2025): private data + " +
  "untrusted content + external communication, coexisting on the same capability " +
  "surface. Any prompt-injection payload that reaches the untrusted-content leg can " +
  "exfiltrate private data via the network leg. Options: (a) split the server into " +
  "three single-leg servers connected by an orchestrator with per-transition review, " +
  "(b) add a destination allowlist to every network-capable tool, (c) add human-in- " +
  "the-loop confirmation on any tool call whose arguments include data read by a " +
  "private-data tool earlier in the same session. Until mitigated, MCP Sentinel " +
  "caps this server's total score at 40.";

const F2_REMEDIATION =
  "The capability graph shows an unrestricted execution surface (command-injection " +
  "chain or unconstrained code/command parameter). Constrain the parameter with " +
  "enum/pattern/maxLength, replace dynamic shell invocation with an allowlisted " +
  "wrapper, and separate command-execution tools from untrusted-content ingestion.";

const F3_REMEDIATION =
  "The capability graph shows a credential-handling node reachable to a network-send " +
  "node with no isolation. Credentials must never coexist with egress in the same " +
  "server; split them, or enforce a strict boundary (destination allowlist + " +
  "per-secret redaction in logs/requests).";

const F6_REMEDIATION =
  "Write+read cycle on a shared data store enables persistent prompt injection: " +
  "attacker poisons a record once, the AI reads the injection on every subsequent " +
  "access. Tag stored content with provenance (human-vs-tool-generated) and sanitize " +
  "on read, or require a human approval for writes that will later be surfaced to " +
  "the agent.";

// ─── Rule class ────────────────────────────────────────────────────────────

class LethalTrifectaRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "capability-graph";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];

    const gathered = gatherF1(context);
    const findings: RuleResult[] = [];

    if (gathered.trifecta_present) {
      findings.push(this.buildF1Finding(gathered));
    }

    for (const companion of gathered.companions) {
      findings.push(this.buildCompanionFinding(companion, gathered));
    }

    return findings;
  }

  // ─── F1 finding ──────────────────────────────────────────────────────────

  private buildF1Finding(g: F1Gathered): RuleResult {
    const pd = primary(g.legs.private_data);
    const ut = primary(g.legs.untrusted_content);
    const ex = primary(g.legs.external_comms);

    const pdLoc: Location = { kind: "tool", tool_name: pd.tool_name };
    const utLoc: Location = { kind: "tool", tool_name: ut.tool_name };
    const exLoc: Location = { kind: "tool", tool_name: ex.tool_name };

    const totalSignals = g.graph.nodes.reduce(
      (sum, n) =>
        sum + n.capabilities.reduce((s, c) => s + c.signals.length, 0),
      0,
    );

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "user-parameter",
        location: pdLoc,
        observed:
          `Private-data leg: tool "${pd.tool_name}" classified ${pd.capability} at ` +
          `${(pd.confidence * 100).toFixed(0)}% confidence from ${pd.signal_count} ` +
          `capability signals.`,
        rationale:
          `Capability-graph multi-signal classifier (${totalSignals} total signals across ` +
          `${g.graph.nodes.length} nodes) identifies at least one tool whose parameter ` +
          `semantics / schema shape / annotations indicate private-data access.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: utLoc,
        observed:
          `Untrusted-content leg: tool "${ut.tool_name}" classified ${ut.capability} at ` +
          `${(ut.confidence * 100).toFixed(0)}% confidence — an attacker-controlled content ` +
          `path. Graph has ${g.graph.edges.length} data-flow edges and ${g.graph.cycles.length} ` +
          `cycles; no isolation boundary separates the untrusted-content node from the ` +
          `private-data or external-comms legs.`,
      })
      .sink({
        sink_type: "network-send",
        location: exLoc,
        observed:
          `External-comms leg: tool "${ex.tool_name}" classified ${ex.capability} at ` +
          `${(ex.confidence * 100).toFixed(0)}% confidence. This is the egress point for the ` +
          `trifecta; a prompt-injection payload delivered through the untrusted-content leg ` +
          `can instruct the agent to exfiltrate data read by the private-data leg through ` +
          `this tool.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `An attacker seeds a payload in a source the untrusted-content leg ingests. The ` +
          `agent executes the payload, reads private data via "${pd.tool_name}", and posts ` +
          `it via "${ex.tool_name}" to an attacker-controlled endpoint. No tool in isolation ` +
          `is dangerous; their coexistence on a single capability surface is.`,
      })
      .factor(
        "private_data_leg_confidence",
        pd.confidence - 0.5,
        `Private-data leg strongest at "${pd.tool_name}" with confidence ` +
          `${(pd.confidence * 100).toFixed(0)}% — attribution: ${pd.attribution}`,
      )
      .factor(
        "untrusted_content_leg_confidence",
        ut.confidence - 0.5,
        `Untrusted-content leg strongest at "${ut.tool_name}" with confidence ` +
          `${(ut.confidence * 100).toFixed(0)}% — attribution: ${ut.attribution}`,
      )
      .factor(
        "external_comms_leg_confidence",
        ex.confidence - 0.5,
        `External-comms leg strongest at "${ex.tool_name}" with confidence ` +
          `${(ex.confidence * 100).toFixed(0)}% — attribution: ${ex.attribution}`,
      )
      .factor(
        "capability_graph_signal_count",
        totalSignals > 10 ? 0.05 : 0.0,
        `${totalSignals} capability signals across ${g.graph.nodes.length} tools — high ` +
          `signal density corroborates the classification.`,
      )
      .reference({
        id: "OWASP-MCP04",
        title: "OWASP MCP Top 10 — MCP04 Data Exfiltration (Willison 'Lethal Trifecta')",
        url: "https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/",
        relevance:
          "Willison's coined term for the exact structural coincidence F1 flags. MCP04 " +
          "treats it as the #1 data-exfiltration pattern in the ecosystem.",
      })
      .verification(stepVerifyPrivateDataLeg(g.legs.private_data))
      .verification(stepVerifyUntrustedLeg(g.legs.untrusted_content))
      .verification(stepVerifyExternalCommsLeg(g.legs.external_comms))
      .verification(stepTraceCrossToolFlow(pd.tool_name, ex.tool_name));

    const chain = capWithLegMin(builder.build(), g.min_leg_confidence);

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: F1_REMEDIATION,
      chain,
    };
  }

  // ─── Companion findings (F2 / F3 / F6) ──────────────────────────────────

  private buildCompanionFinding(
    companion: CompanionPattern,
    g: F1Gathered,
  ): RuleResult {
    const tools = companionTools(companion);
    const primaryTool = tools[0] ?? "<no-tool>";
    const primaryLoc: Location = { kind: "tool", tool_name: primaryTool };
    const secondary =
      tools.length > 1
        ? ({ kind: "tool", tool_name: tools[1] } as Location)
        : primaryLoc;
    const description = companionDescription(companion);
    const confidence = companionConfidence(companion);

    const [sourceType, sinkType, impactType, remediation, severity, owasp, mitre] =
      companionMeta(companion);

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: sourceType,
        location: primaryLoc,
        observed:
          `Companion pattern ${companion.companion} observed during F1's capability-graph ` +
          `pass (origin=${companion.origin}): ${description}`,
        rationale:
          `Emitted as a companion to F1 because the same graph traversal that detects the ` +
          `trifecta surfaces this pattern as a by-product. Captured here so the registry ` +
          `records ${companion.companion} rather than silently folding it into F1's evidence.`,
      })
      .propagation({
        propagation_type: "cross-tool-flow",
        location: secondary,
        observed:
          `Tools involved: ${tools.join(", ") || "<none>"}. Graph pass recorded ` +
          `${g.graph.edges.length} edges and ${g.graph.cycles.length} cycles — this ` +
          `pattern lives inside that structure.`,
      })
      .sink({
        sink_type: sinkType,
        location: primaryLoc,
        observed:
          `Sink for the ${companion.companion} pattern — see the companion rule's CHARTER ` +
          `for the canonical treatment.`,
      })
      .impact({
        impact_type: impactType,
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `Capability-graph / schema-inference identified this pattern as a by-product of ` +
          `the F1 analysis pass. Treat as a precursor condition feeding F1's structural ` +
          `risk.`,
      })
      .factor(
        "companion_of_F1",
        0.0,
        `Emitted as a companion of F1 — the parent rule's capability-graph pass surfaced ` +
          `this ${companion.companion} pattern (origin=${companion.origin}).`,
      )
      .factor(
        "pattern_confidence",
        confidence - 0.5,
        `Pattern-specific confidence ${(confidence * 100).toFixed(0)}% from the underlying ` +
          `analyzer.`,
      )
      .reference({
        id: `OWASP-${owasp}`,
        title: `OWASP MCP Top 10 — ${owasp}`,
        relevance: `${companion.companion} maps to ${owasp}. See the companion rule's CHARTER ` +
          `for threat references specific to that category.`,
      })
      .verification(stepVerifyCompanion(companion));

    const chain = clampConfidence(builder.build(), F1_CONFIDENCE_CAP);

    return {
      rule_id: companion.companion,
      severity,
      owasp_category: owasp,
      mitre_technique: mitre,
      remediation,
      chain,
    };
  }
}

// ─── Companion metadata tables ─────────────────────────────────────────────

/**
 * Narrow tuple of companion-rule metadata. Table-driven so adding a fourth
 * companion in the future is one typed entry, not a switch-statement dig.
 */
function companionMeta(companion: CompanionPattern): [
  "external-content" | "user-parameter",
  "command-execution" | "credential-exposure" | "config-modification",
  "data-exfiltration" | "credential-theft" | "config-poisoning",
  string,
  "critical" | "high" | "medium",
  "MCP04-data-exfiltration" | "MCP03-command-injection" | "MCP06-excessive-permissions" | "MCP01-prompt-injection",
  string | null,
] {
  if (companion.companion === "F2") {
    return [
      "external-content",
      "command-execution",
      "data-exfiltration",
      F2_REMEDIATION,
      "critical",
      "MCP03-command-injection",
      "AML.T0054",
    ];
  }
  if (companion.companion === "F3") {
    return [
      "user-parameter",
      "credential-exposure",
      "credential-theft",
      F3_REMEDIATION,
      "critical",
      "MCP04-data-exfiltration",
      "AML.T0057",
    ];
  }
  // F6
  return [
    "external-content",
    "config-modification",
    "config-poisoning",
    F6_REMEDIATION,
    "high",
    "MCP01-prompt-injection",
    "AML.T0054.001",
  ];
}

function companionTools(companion: CompanionPattern): string[] {
  if (companion.origin === "graph") {
    if (companion.pattern.type === "unrestricted_access") return [];
    return (companion.pattern as { tools_involved: string[] }).tools_involved;
  }
  return (companion.pattern as { tools: string[] }).tools;
}

function companionDescription(companion: CompanionPattern): string {
  if (companion.origin === "graph") {
    return (companion.pattern as { description: string }).description;
  }
  return (companion.pattern as { evidence: string }).evidence;
}

function companionConfidence(companion: CompanionPattern): number {
  return (companion.pattern as { confidence: number }).confidence;
}

// ─── Confidence helpers ────────────────────────────────────────────────────

/**
 * F1-specific confidence adjuster: after the builder computes its base + factors,
 * clamp the result to the min-of-leg-maxes AND to the charter cap. The min-of-
 * leg-maxes is the "weakest link" rule from the charter — a 0.51/0.51/0.51
 * trifecta cannot report higher confidence than its weakest leg.
 */
function capWithLegMin(chain: EvidenceChain, minLeg: number): EvidenceChain {
  const capped = clampConfidence(chain, F1_CONFIDENCE_CAP);
  if (capped.confidence <= minLeg) return capped;
  capped.confidence_factors.push({
    factor: "weakest_leg_floor",
    adjustment: minLeg - capped.confidence,
    rationale:
      `F1 confidence clamped to the weakest of the three legs (${(minLeg * 100).toFixed(0)}%) — ` +
      `the trifecta is only as strong as its least-confident leg.`,
  });
  capped.confidence = minLeg;
  return capped;
}

function clampConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `F1 charter caps confidence at ${cap} — capability classification is multi-signal ` +
      `probabilistic and graph reachability is inferred, not observed at runtime.`,
  });
  chain.confidence = cap;
  return chain;
}

function primary(contributions: LegContribution[]): LegContribution {
  // Strongest-first: highest confidence node is the canonical leg witness.
  return [...contributions].sort((a, b) => b.confidence - a.confidence)[0];
}

// ─── Registration ─────────────────────────────────────────────────────────

registerTypedRuleV2(new LethalTrifectaRule());

export { LethalTrifectaRule };
