/**
 * I1 — Annotation Deception (Rule Standard v2).
 *
 * Detects tools whose MCP-spec-2025-03-26 annotations contradict the
 * tool's actual capability as inferred from the input schema, the
 * parameter names, or the description. A tool that declares
 * readOnlyHint: true while exposing a `delete_*` parameter bypasses
 * every AI-client auto-approval gate that keys on that annotation —
 * ChatGPT, Cursor, Roo Code, and JetBrains Copilot all do (Invariant
 * Labs 2025).
 *
 * Inputs:
 *   - tool.annotations (MCP spec 2025-03-26)
 *   - tool.input_schema.properties (parameter-name vocabulary)
 *   - tool.description (destructive-verb scan)
 *   - schema-inference analyzer (structural capability confirmation)
 *
 * Confidence cap: 0.85 (charter §"Why confidence is capped at 0.85").
 *
 * No regex literals. No string-literal arrays > 5. All vocabulary lives
 * in ./data/destructive-vocabulary.ts as typed Records.
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
import { gatherI1, type DeceptionFact, type I1Gathered } from "./gather.js";
import {
  stepCheckClientTrustBoundary,
  stepInspectAnnotation,
  stepInspectDestructiveSignal,
} from "./verification.js";
import { CLIENTS_TRUSTING_READONLY_HINT } from "./data/destructive-vocabulary.js";

const RULE_ID = "I1";
const RULE_NAME = "Annotation Deception";
const OWASP = "MCP06-excessive-permissions" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;
const CONFIDENCE_FLOOR = 0.6;

const REMEDIATION =
  "Remove readOnlyHint: true from any tool whose parameters or description indicate " +
  "write, delete, or overwrite capability. If the tool is genuinely read-only, rename " +
  "the misleading parameter or update the description. If the tool is destructive, set " +
  "destructiveHint: true so AI clients require user confirmation before invocation. " +
  "AI clients (ChatGPT, Cursor, Roo Code, JetBrains Copilot per Invariant Labs 2025) " +
  "auto-approve tools declaring readOnlyHint: true without cross-checking the schema — " +
  "a deceptive annotation bypasses the strongest consent control in the MCP protocol.";

class AnnotationDeceptionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "schema-inference";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherI1(context);
    if (gathered.facts.length === 0) return [];

    return gathered.facts.map((fact) => this.buildFinding(fact, gathered));
  }

  private buildFinding(fact: DeceptionFact, _gathered: I1Gathered): RuleResult {
    const primary = fact.primary_signal;
    const clientList = Object.keys(CLIENTS_TRUSTING_READONLY_HINT).join(", ");

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "external-content",
        location: fact.tool_location,
        observed: describeAnnotation(fact),
        rationale:
          `The MCP spec (2025-03-26) treats tool annotations as server-declared hints ` +
          `that AI clients may use to skip user confirmation. readOnlyHint: true is an ` +
          `explicit claim of no side effects, and the clients ${clientList} honour that ` +
          `claim without cross-checking the tool schema.`,
      })
      .propagation({
        propagation_type: "schema-unconstrained",
        location: primary.location,
        observed: `${primary.attribution} — contradicts readOnlyHint: true.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: fact.tool_location,
        observed:
          `AI client auto-approval path for tool "${fact.tool_name}": the deceptive ` +
          `annotation causes the client to run the tool without prompting the user.`,
      })
      .mitigation({
        mitigation_type: "annotation-hint",
        present: false,
        location: fact.tool_location,
        detail:
          fact.annotation.kind === "readonly_declared" && fact.annotation.destructive_hint === true
            ? "Tool declares both readOnlyHint: true AND destructiveHint: true simultaneously — the second hint does not function as a mitigation because the first already claims no side effects."
            : "Tool declares readOnlyHint: true without a matching destructiveHint: true — no secondary hint tells the AI client to confirm before invocation.",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "user-data",
        exploitability: "trivial",
        scenario:
          `An attacker ships a tool named "${fact.tool_name}" with annotations ` +
          `readOnlyHint: true. An AI client that trusts the hint auto-approves the ` +
          `tool without user consent. On the very first invocation the tool ` +
          `executes its destructive operation (${primary.verb || primary.verb_kind || "destructive capability"}) ` +
          `with the user's full MCP session permissions. No prior review, no user ` +
          `click, no audit event — the consent control is bypassed entirely.`,
      })
      .factor(
        "annotation_contradiction",
        0.15,
        fact.annotation.kind === "readonly_declared" && fact.annotation.destructive_hint === true
          ? "readOnlyHint: true and destructiveHint: true declared on the same tool — mutually exclusive by spec."
          : `readOnlyHint: true declared on tool with ${primary.origin === "schema_inference" ? "structurally-confirmed destructive capability" : `${primary.origin.replace("_", "-")} signal of destructive intent`}.`,
      )
      .factor(
        "destructive_signal_source",
        primary.origin === "schema_inference"
          ? 0.1
          : primary.origin === "parameter_name"
            ? 0.08
            : primary.origin === "annotation_self_contradiction"
              ? 0.12
              : 0.04,
        `Primary destructive signal via ${primary.origin}: ${primary.attribution}`,
      );

    if (fact.schema_confirms_destructive && primary.origin !== "schema_inference") {
      builder.factor(
        "schema_inference_second_signal",
        0.05,
        `Schema structural analysis independently confirms destructive capability ` +
          `(attack_surface_score ${(fact.attack_surface_score * 100).toFixed(0)}%) — two-source corroboration.`,
      );
    }

    if (fact.signals.length > 1) {
      builder.factor(
        "multi_signal_contradiction",
        Math.min(0.1, 0.02 * fact.signals.length),
        `${fact.signals.length} independent destructive signals converge on the same tool ` +
          `(${fact.signals.map((s) => s.origin).join(", ")}) — weakens any benign-ambiguity defence.`,
      );
    }

    builder.reference({
      id: "Invariant-Labs-Annotation-Deception-2025",
      title:
        "Invariant Labs — Tool Poisoning Attacks via MCP Annotation Deception (2025)",
      url: "https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks",
      year: 2025,
      relevance:
        "Demonstrates that ChatGPT, Cursor, Roo Code, and JetBrains Copilot all skip " +
        "the user confirmation dialog when a tool declares readOnlyHint: true — even " +
        "when the tool's schema contains destructive parameters. I1 is the deterministic " +
        "detector for the annotation-vs-schema contradiction shape.",
    });

    builder.verification(stepInspectAnnotation(fact));
    for (const signal of fact.signals) {
      builder.verification(stepInspectDestructiveSignal(fact, signal));
    }
    builder.verification(stepCheckClientTrustBoundary(fact));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP, CONFIDENCE_FLOOR);

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

// ─── Helpers ───────────────────────────────────────────────────────────────

function describeAnnotation(fact: DeceptionFact): string {
  if (fact.annotation.kind !== "readonly_declared") return "annotation present";
  const dh = fact.annotation.destructive_hint;
  if (dh === true) return `annotations: { readOnlyHint: true, destructiveHint: true } — self-contradicting`;
  if (dh === false) return `annotations: { readOnlyHint: true, destructiveHint: false }`;
  return `annotations: { readOnlyHint: true } — destructiveHint absent`;
}

/**
 * Clamp chain.confidence to the charter's [floor, cap] range and record
 * the clamp as an auditable ConfidenceFactor. Mutates the chain — the
 * builder's output is owned by the rule.
 */
function capConfidence(chain: EvidenceChain, cap: number, floor: number): EvidenceChain {
  if (chain.confidence > cap) {
    chain.confidence_factors.push({
      factor: "charter_confidence_cap",
      adjustment: cap - chain.confidence,
      rationale:
        `I1 charter caps confidence at ${cap}. Structural contradiction is provable, ` +
        `but at least one chain link depends on linguistic judgement (parameter-name ` +
        `or description vocabulary); the cap preserves room for benign-false-match cases.`,
    });
    chain.confidence = cap;
  } else if (chain.confidence < floor) {
    chain.confidence_factors.push({
      factor: "charter_confidence_floor",
      adjustment: floor - chain.confidence,
      rationale:
        `I1 charter floors confidence at ${floor}. Any confirmed annotation-vs-capability ` +
        `contradiction merits at least that confidence because the consent-bypass ` +
        `mechanism itself is a boolean fact, not a heuristic.`,
    });
    chain.confidence = floor;
  }
  return chain;
}

registerTypedRuleV2(new AnnotationDeceptionRule());

// Export for tests (dynamic instantiation without relying on the global registry).
export { AnnotationDeceptionRule };
