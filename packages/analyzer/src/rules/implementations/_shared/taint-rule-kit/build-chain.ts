/**
 * Shared taint-rule-kit — evidence-chain builder.
 *
 * Each rule passes in its own rule-specific mapping (which EvidenceChain
 * source_type / sink_type / impact_type / CVE / threat reference it wants
 * on the chain) and the shared function assembles the links in the same
 * order every time:
 *
 *   source → propagation(...hops) → sink → mitigation → impact → factors →
 *   reference → verification steps
 *
 * The function returns an *unsealed* builder so the rule's index.ts can
 * append rule-specific factors (charter cap, rule-unique edge cases) and
 * rule-specific verification steps before calling `.build()`.
 *
 * Zero regex literals. Zero string-literal arrays > 5.
 */

import {
  EvidenceChainBuilder,
  type MitigationLink,
  type SinkLink,
  type SourceLink,
  type ImpactLink,
  type VerificationStep,
  type ThreatReference,
} from "../../../../evidence.js";
import type { Location } from "../../../location.js";
import type { TaintFact, TaintPathStep } from "./types.js";

// ─── Per-rule descriptor (passed from rule index.ts) ─────────────────────

export interface TaintChainDescriptor {
  ruleId: string;
  /** How the chain's source link should be classified. */
  sourceType: SourceLink["source_type"];
  /** How the chain's sink link should be classified. */
  sinkType: SinkLink["sink_type"];
  /** CVE / CWE string attached to sink.cve_precedent. */
  cvePrecedent: string;
  /** Human rationale for the source link. */
  sourceRationale: (fact: TaintFact) => string;
  /** How the impact link is classified. */
  impactType: ImpactLink["impact_type"];
  /** Impact scope. */
  impactScope: ImpactLink["scope"];
  /** Function producing the impact scenario narrative. */
  impactScenario: (fact: TaintFact) => string;
  /** Threat reference attached to the chain. */
  threatReference: ThreatReference;
  /** Human-readable description inserted into mitigation-absent rationale. */
  unmitigatedDetail: string;
  /** Human-readable description inserted into mitigation-present rationale. */
  mitigatedCharterKnownDetail: (sanitiserName: string) => string;
  /** Human-readable description inserted into mitigation-present-but-unknown rationale. */
  mitigatedCharterUnknownDetail: (sanitiserName: string) => string;
}

// ─── Builder helpers ────────────────────────────────────────────────────

/**
 * Produce an EvidenceChainBuilder pre-populated with:
 *   • source link
 *   • one propagation link per path hop
 *   • sink link
 *   • mitigation link
 *   • impact link
 *   • base factors ("ast_confirmed" / "lightweight_confirmed" + hop factor)
 *   • threat reference
 *
 * The returned builder is intentionally NOT built — rule code appends
 * rule-specific factors / verification steps, then calls `.build()`.
 */
export function buildTaintChain(
  fact: TaintFact,
  descriptor: TaintChainDescriptor,
): EvidenceChainBuilder {
  const builder = new EvidenceChainBuilder();

  builder.source({
    source_type: descriptor.sourceType,
    location: fact.sourceLocation,
    observed: fact.sourceExpression,
    rationale: descriptor.sourceRationale(fact),
  });

  for (const step of fact.path) {
    builder.propagation({
      propagation_type: mapStepToPropagation(step),
      location: step.location,
      observed: step.expression,
    });
  }

  builder.sink({
    sink_type: descriptor.sinkType,
    location: fact.sinkLocation,
    observed: fact.sinkExpression,
    cve_precedent: descriptor.cvePrecedent,
  });

  builder.mitigation(buildMitigationLink(fact, descriptor));

  builder.impact({
    impact_type: descriptor.impactType,
    scope: descriptor.impactScope,
    exploitability: fact.path.length === 0 ? "trivial" : "moderate",
    scenario: descriptor.impactScenario(fact),
  });

  // Base factors — every taint fact records which analyser confirmed it
  // and the hop count (interprocedural distance).
  if (fact.analyser === "ast") {
    builder.factor(
      "ast_confirmed",
      0.15,
      `AST taint analyser traced data flow from ${descriptor.ruleId} source to sink ` +
        `with ${fact.path.length} intermediate hop(s) — strongest static proof the rule ` +
        `can produce.`,
    );
  } else {
    builder.factor(
      "lightweight_taint_fallback",
      0.05,
      `AST taint analysis could not prove the flow (typically a Python fixture or ` +
        `a parser-defeating construct); the lightweight regex-based taint analyser did. ` +
        `Confidence remains above the direct-match floor because a source→sink edge was ` +
        `still observed.`,
    );
  }

  builder.factor(
    "interprocedural_hops",
    fact.path.length === 0 ? 0.05 : fact.path.length >= 3 ? -0.05 : 0.02,
    fact.path.length === 0
      ? `Direct source→sink flow (zero hops) — source expression is the sink's ` +
        `first argument on the same call.`
      : fact.path.length >= 3
        ? `${fact.path.length}-hop path — every additional hop introduces a small chance ` +
          `the taint was broken by an unrecognised transform, so the factor is slightly ` +
          `negative.`
        : `${fact.path.length}-hop path — short enough that every step is independently ` +
          `verifiable.`,
  );

  if (fact.sanitiser && !fact.sanitiser.charterKnown) {
    builder.factor(
      "unverified_sanitizer_identity",
      0.1,
      `Sanitiser "${fact.sanitiser.name}" is not on the ${descriptor.ruleId} charter list ` +
        `of audited safeguards. A reviewer must audit its body before accepting the ` +
        `informational severity (see CHARTER edge case on sanitiser-identity bypass).`,
    );
  }

  builder.reference(descriptor.threatReference);

  return builder;
}

function mapStepToPropagation(step: TaintPathStep): "variable-assignment" | "template-literal" | "function-call" | "direct-pass" {
  switch (step.kind) {
    case "assignment":
    case "destructure":
      return "variable-assignment";
    case "template-embed":
      return "template-literal";
    case "function-call":
      return "function-call";
    default:
      return "direct-pass";
  }
}

function buildMitigationLink(
  fact: TaintFact,
  descriptor: TaintChainDescriptor,
): Omit<MitigationLink, "type"> {
  if (!fact.sanitiser) {
    return {
      mitigation_type: "input-validation",
      present: false,
      location: fact.sinkLocation,
      detail: descriptor.unmitigatedDetail,
    };
  }
  return {
    mitigation_type: "sanitizer-function",
    present: true,
    location: fact.sanitiser.location,
    detail: fact.sanitiser.charterKnown
      ? descriptor.mitigatedCharterKnownDetail(fact.sanitiser.name)
      : descriptor.mitigatedCharterUnknownDetail(fact.sanitiser.name),
  };
}

// ─── Reusable verification-step builders ─────────────────────────────────

export function stepInspectTaintSource(fact: TaintFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm the expression at this position really is an ` +
      `untrusted ${fact.sourceCategory} source. If the node is a hardcoded literal ` +
      `or a trusted constant, the taint chain does not hold and the finding should ` +
      `be dismissed.`,
    target: fact.sourceLocation,
    expected_observation:
      `The expression \`${truncate(fact.sourceExpression, 120)}\` reads from an external ` +
      `input surface categorised by the taint analyser as ${fact.sourceCategory}.`,
  };
}

export function stepInspectTaintSink(fact: TaintFact, sinkVerb: string): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm the call at this position is ${sinkVerb} and the ` +
      `argument the taint analyser flagged is the one produced by the source above. ` +
      `Safe equivalents (parameterised queries, SafeLoader, execFile, argv arrays) ` +
      `would have caused the analyser to skip the call — their presence here would ` +
      `be a scanner bug.`,
    target: fact.sinkLocation,
    expected_observation:
      `A ${sinkVerb} call of the form \`${truncate(fact.sinkExpression, 120)}\` ` +
      `whose argument derives from the source at the previous step.`,
  };
}

export function stepTraceTaintPath(fact: TaintFact): VerificationStep {
  const target: Location =
    fact.path.length > 0 ? fact.path[0].location : fact.sinkLocation;
  const observation =
    fact.path.length === 0
      ? `Direct source→sink flow (zero propagation hops). Source and sink are the ` +
        `same argument of the same call — exploitability = "trivial".`
      : `Walk the following ${fact.path.length} hop(s) in order and confirm each is a ` +
        `real data-flow step (assignment, destructure, return, template embed, parameter ` +
        `bind): ` + fact.path.map(renderHop).join(" → ");
  return {
    step_type: "trace-flow",
    instruction:
      `Follow the propagation chain the taint analyser reported. Each hop must be a ` +
      `real data-flow step (not an unrelated line that happens to mention the variable ` +
      `name). A broken hop invalidates the chain.`,
    target,
    expected_observation: observation,
  };
}

export function stepInspectTaintSanitiser(fact: TaintFact): VerificationStep | null {
  if (!fact.sanitiser) return null;
  const name = fact.sanitiser.name;
  const instruction = fact.sanitiser.charterKnown
    ? `The sanitiser \`${name}\` is on the charter-audited list. Confirm the binding ` +
      `resolves to the library function and not a locally-shadowed identifier — an ` +
      `override that imports \`${name}\` but re-exports a no-op still gets picked up by ` +
      `name alone.`
    : `The sanitiser \`${name}\` is NOT on the charter-audited list. Open its ` +
      `definition and confirm it actually transforms the input — if the body merely ` +
      `calls toString() / JSON.stringify() / returns the input unchanged, the finding ` +
      `should be re-escalated from informational to critical.`;
  return {
    step_type: "inspect-source",
    instruction,
    target: fact.sanitiser.location,
    expected_observation: fact.sanitiser.charterKnown
      ? `\`${name}\` is imported from a charter-audited module and invoked on the ` +
        `tainted value before it reaches the sink.`
      : `\`${name}\` is a project-local helper whose body a reviewer MUST audit before ` +
        `accepting the informational severity.`,
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────

function renderHop(step: TaintPathStep): string {
  const loc = step.location;
  const pos = loc.kind === "source" ? `${loc.file}:${loc.line}` : "<non-source>";
  return `${step.kind}@${pos} (${truncate(step.expression, 60)})`;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

// ─── Confidence cap helper ──────────────────────────────────────────────

/**
 * Clamp a chain's confidence to the rule-specific cap, recording the
 * reason in confidence_factors so the cap is auditable.
 */
export function capConfidence(
  chain: { confidence: number; confidence_factors: Array<{ factor: string; adjustment: number; rationale: string }> },
  cap: number,
  ruleId: string,
): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `${ruleId} charter caps AST-confirmed in-file taint at ${cap}. The remaining gap ` +
      `to 1.0 is reserved for runtime controls the static analyser cannot observe ` +
      `(ORM wrappers, schema validators, argv-normalising libraries, container-level ` +
      `sandboxes).`,
  });
  chain.confidence = cap;
}
