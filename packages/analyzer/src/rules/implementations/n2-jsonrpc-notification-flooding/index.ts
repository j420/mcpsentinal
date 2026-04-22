/**
 * N2 — JSON-RPC Notification Flooding (Rule Standard v2).
 *
 * Migrated out of jsonrpc-protocol-v2.ts on 2026-04-21. See CHARTER.md for
 * the threat narrative, evidence contract, and confidence ceiling.
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
import { gather, type NotificationFlood } from "./gather.js";
import {
  verifyEmissionInLoop,
  verifyNoThrottleVocabulary,
  verifyBackpressureAbsent,
  toLocation,
} from "./verification.js";

const RULE_ID = "N2";
const RULE_NAME = "JSON-RPC Notification Flooding";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.85;

const REMEDIATION =
  "Bound the outbound notification queue (recommended max 100 per subscription) " +
  "and apply drop-oldest backpressure. Add per-client rate limits on notify/emit/send* " +
  "calls. JSON-RPC notifications have no response — servers MUST implement explicit " +
  "flow control; the protocol does not.";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N2JsonRpcNotificationFlooding implements TypedRuleV2 {
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

  private buildFinding(fact: NotificationFlood): RuleResult {
    const b = new EvidenceChainBuilder();
    const loc: Location = toLocation(fact.location);

    b.source({
      source_type: "external-content",
      location: loc,
      observed: fact.location.snippet,
      rationale:
        `Notification emission via ${fact.call_expression}() inside a ${fact.loop_context}. ` +
        `JSON-RPC notifications (Section 4.1) receive no response, so the producer ` +
        `has no ACK-driven throttle — each loop iteration writes wire traffic.`,
    });

    b.sink({
      sink_type: "network-send",
      location: loc,
      observed:
        `${fact.call_expression}() — per-iteration unsolicited wire emit. ` +
        `Loop context: ${fact.loop_context}.`,
    });

    b.mitigation({
      mitigation_type: "rate-limit",
      present: false,
      location: loc,
      detail:
        `No throttle/debounce/rateLimit/sleep/delay/setTimeout call and no break or ` +
        `return in the emission path` +
        (fact.location.enclosing_function
          ? ` (${fact.location.enclosing_function})`
          : "") +
        `. Parity JSON-RPC resilience guidance (issue #557) ` +
        `and the broader slowloris WebSocket class require bounded outbound queues.`,
    });

    b.impact({
      impact_type: "denial-of-service",
      scope: "connected-services",
      exploitability: "trivial",
      scenario:
        `An adversary who can trigger this producer loop (one inbound request, or a ` +
        `connection-establishment event) receives N unsolicited notifications back. ` +
        `At wire speed this saturates the client's receive buffer and exhausts the ` +
        `transport's outbound queue.`,
    });

    b.factor(
      "notification_emission_in_unbounded_loop",
      0.12,
      `AST-confirmed: ${fact.verb_identifier}() emits from inside ${fact.loop_context}; ` +
        `enclosing function contains no throttle vocabulary.`,
    );

    b.reference({
      id: "JSONRPC-2.0-SEC-4.1",
      title: "JSON-RPC 2.0 Specification — Notification",
      url: "https://www.jsonrpc.org/specification#notification",
      relevance:
        "Section 4.1 defines Notifications as fire-and-forget; the protocol provides no ACK or backpressure channel, so rate control must be enforced at the server.",
    });

    b.verification(verifyEmissionInLoop(fact));
    b.verification(verifyNoThrottleVocabulary(fact));
    b.verification(verifyBackpressureAbsent(fact));

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

registerTypedRuleV2(new N2JsonRpcNotificationFlooding());
