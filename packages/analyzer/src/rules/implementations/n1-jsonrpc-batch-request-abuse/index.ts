/**
 * N1 — JSON-RPC Batch Request Abuse (Rule Standard v2).
 *
 * See CHARTER.md for the threat narrative and audit contract. Summary:
 * detect JSON-RPC servers that iterate batch request arrays with no size
 * guard, enabling 1-request → N-work amplification DoS.
 *
 * Migrated out of the legacy `jsonrpc-protocol-v2.ts` shared file on 2026-04-21.
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
import { gather, type BatchFact } from "./gather.js";
import {
  verifyIterationIsUnbounded,
  verifyEnclosingScopeHasNoLimit,
  verifyNoTransportLayerLimit,
} from "./verification.js";

const RULE_ID = "N1";
const RULE_NAME = "JSON-RPC Batch Request Abuse";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.90;

const REMEDIATION =
  "Enforce a maximum batch size (recommended 20-25). Reject oversized batches with " +
  "JSON-RPC error code -32600 (Invalid Request). Add per-batch timeout and memory " +
  "limits. JSON-RPC 2.0 Section 6 permits batching but imposes no ceiling — the " +
  "server MUST enforce one.";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N1JsonRpcBatchRequestAbuse implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code) return [];
    if (isTestFile(context.source_code)) return [];

    const { facts } = gather(context.source_code);
    if (facts.length === 0) return [];

    // One finding per file — if multiple call sites match, report the first.
    const fact = facts[0];
    return [this.buildFinding(fact)];
  }

  private buildFinding(fact: BatchFact): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `source_code:line ${fact.location.line}`,
      observed: fact.location.snippet || `${fact.receiver_name}.${fact.iteration_method}(...)`,
      rationale:
        `A JSON-RPC request body reaches this call as an attacker-controlled array ` +
        `(${fact.fact_kind === "guarded-iteration" ? "Array.isArray guard matched" : "batch-named receiver"}). ` +
        `JSON-RPC 2.0 Section 6 permits arrays of arbitrary length; MCP inherits this ` +
        `via Streamable HTTP transport (spec 2025-03-26).`,
    });

    builder.sink({
      sink_type: "code-evaluation",
      location: `source_code:line ${fact.location.line}`,
      observed:
        `${fact.receiver_name}.${fact.iteration_method}(...) — synchronous per-entry ` +
        `dispatch multiplies server work by batch length.`,
    });

    builder.mitigation({
      mitigation_type: "rate-limit",
      present: false,
      location:
        fact.location.enclosing_function
          ? `function ${fact.location.enclosing_function}`
          : `enclosing scope of line ${fact.location.line}`,
      detail:
        `No size guard, .slice, throttle, debounce, or rateLimit vocabulary detected ` +
        `in the enclosing function scope. JSON-RPC batch amplification class (CometBFT ` +
        `issue #2867, LSP PR #1651) remains open.`,
    });

    builder.impact({
      impact_type: "denial-of-service",
      scope: "server-host",
      exploitability: "trivial",
      scenario:
        `A single HTTP POST containing a JSON array of 10³-10⁶ requests exhausts CPU ` +
        `and memory. Per-method side effects (DB writes, remote API calls) are ` +
        `amplified by batch length. One TCP connection sustains the attack.`,
    });

    builder.factor(
      "unbounded_batch_iteration",
      0.12,
      `AST-confirmed iteration of batch-shaped value (${fact.receiver_name}.${fact.iteration_method}) ` +
        `with no limit or throttle vocabulary in the enclosing function.`,
    );

    if (fact.fact_kind === "guarded-iteration") {
      builder.factor(
        "array_isarray_guard_present",
        0.05,
        `Preceded by an Array.isArray check on a batch-named argument — confirms the ` +
          `handler explicitly recognises the batch shape but does not bound it.`,
      );
    }

    builder.reference({
      id: "JSONRPC-2.0-SEC-6",
      title: "JSON-RPC 2.0 Specification — Batch",
      url: "https://www.jsonrpc.org/specification#batch",
      relevance:
        "Section 6 defines batching as an array of Request objects but does not mandate a size limit; servers are responsible for rejecting oversized batches.",
    });

    builder.verification(verifyIterationIsUnbounded(fact.location, fact.iteration_method));
    builder.verification(verifyEnclosingScopeHasNoLimit(fact.location, fact.location.enclosing_function));
    builder.verification(verifyNoTransportLayerLimit(fact.location));

    const raw = builder.build();

    // Cap confidence per CHARTER.md (0.90 ceiling).
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

registerTypedRuleV2(new N1JsonRpcBatchRequestAbuse());
