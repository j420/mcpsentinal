/**
 * N8 — Cancellation Race Condition (Rule Standard v2).
 *
 * Aligns with rules/N8-cancellation-race-condition.yaml. The legacy
 * jsonrpc-protocol-v2.ts implementation under id 'N8' targeted ping/heartbeat
 * side channels — orthogonal to this YAML. This migration implements the
 * actual YAML intent: cancel handlers that mutate state without atomic guards.
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
import { gather, type CancelRaceFact } from "./gather.js";
import {
  verifyCancelHandlerMutates,
  verifyNoTransactionOrLock,
  verifyRuntimeRaceIsReproducible,
  toLocation,
} from "./verification.js";

const RULE_ID = "N8";
const RULE_NAME = "Cancellation Race Condition";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.80;

const REMEDIATION =
  "Wrap cancellable mutations in an atomic transaction. On cancel, invoke " +
  "transaction.rollback() rather than manually deleting partial state. For " +
  "filesystem writes that cannot be transactional, write to a temp path and " +
  "rename only after success — on cancel, unlink the temp path. Hold a mutex " +
  "between the 'is committed?' check and the rollback to close the TOCTOU race. " +
  "MCP spec 2025-03-26 §5.3 defines cancellation as advisory — the server MUST " +
  "tolerate cancels arriving after completion.";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N8CancellationRaceCondition implements TypedRuleV2 {
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

  private buildFinding(fact: CancelRaceFact): RuleResult {
    const b = new EvidenceChainBuilder();
    const loc: Location = toLocation(fact.location);

    b.source({
      source_type: "external-content",
      location: loc,
      observed: fact.location.snippet,
      rationale:
        `Cancellation arrives asynchronously via ${fact.handler_kind}. MCP spec ` +
        `2025-03-26 §5.3 states the operation may already have completed.`,
    });

    b.propagation({
      propagation_type: "function-call",
      location: loc,
      observed:
        `Cancel signal reaches a mutation call (${fact.mutation_verb}) in the same ` +
        `scope. No atomic bracket separates read-state-then-mutate.`,
    });

    b.sink({
      sink_type: "file-write",
      location: loc,
      observed:
        `${fact.mutation_verb} executed on the cancel path. If the original operation ` +
        `has already committed, this mutation corrupts now-valid state.`,
    });

    b.mitigation({
      mitigation_type: "sanitizer-function",
      present: false,
      location: loc,
      detail:
        `No transaction/atomic/lock/mutex vocabulary in the enclosing scope` +
        (fact.location.enclosing_function
          ? ` (${fact.location.enclosing_function})`
          : "") +
        `. The cancel-and-mutate path is a CWE-367 TOCTOU race.`,
    });

    b.impact({
      impact_type: "config-poisoning",
      scope: "user-data",
      exploitability: "moderate",
      scenario:
        `Attacker (or a legitimate but poorly-timed client) issues a cancel after the ` +
        `operation has committed. The cancel handler rolls back / deletes / rewrites ` +
        `state that the original operation's completion callback still believes is ` +
        `valid. The system reports success to the caller while persisting a corrupted ` +
        `or deleted artifact.`,
    });

    b.factor(
      "cancellation_without_atomic_guard",
      0.10,
      `AST-confirmed: ${fact.handler_kind} cancel path contains ${fact.mutation_verb}; ` +
        `enclosing function lacks transaction/lock vocabulary.`,
    );

    b.reference({
      id: "CWE-367",
      title: "CWE-367 Time-Of-Check Time-Of-Use Race",
      url: "https://cwe.mitre.org/data/definitions/367.html",
      relevance:
        "Cancel-check followed by rollback/delete without atomic guard reproduces the TOCTOU race class.",
    });

    b.verification(verifyCancelHandlerMutates(fact));
    b.verification(verifyNoTransactionOrLock(fact));
    b.verification(verifyRuntimeRaceIsReproducible(fact));

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

registerTypedRuleV2(new N8CancellationRaceCondition());
