/**
 * N10 — Incomplete Handshake Denial of Service (Rule Standard v2).
 *
 * Aligns with rules/N10-incomplete-handshake-dos.yaml. The legacy
 * jsonrpc-protocol-v2.ts implementation of N10 targeted cancellation-token
 * injection — orthogonal to this concern. This migration implements the
 * actual YAML intent: servers that accept connections without enforcing a
 * handshake deadline, enabling Slowloris-class resource exhaustion.
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
import { gather, type HandshakeFact } from "./gather.js";
import {
  verifyAcceptWithoutDeadline,
  verifyNoMaxConnections,
  verifySlowlorisReproducible,
} from "./verification.js";

const RULE_ID = "N10";
const RULE_NAME = "Incomplete Handshake Denial of Service";
const OWASP = "MCP07-insecure-config";
const SEVERITY = "high" as const;
const CONFIDENCE_CEILING = 0.82;

const REMEDIATION =
  "Enforce a handshake deadline: set WebSocketServer { handshakeTimeout: 30000 }, " +
  "http.Server headersTimeout + requestTimeout, or wrap the initialize read in " +
  "AbortSignal.timeout(30_000) / Promise.race. Additionally set server.maxConnections " +
  "to cap total open slots. MCP spec 2025-03-26 does not mandate these — the server " +
  "MUST enforce them; otherwise the lifecycle gate becomes a Slowloris vector (CWE-400).";

function isTestFile(source: string): boolean {
  return /(?:__tests?__|\.(?:test|spec)\.)/.test(source);
}

export class N10IncompleteHandshakeDoS implements TypedRuleV2 {
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

  private buildFinding(fact: HandshakeFact): RuleResult {
    const b = new EvidenceChainBuilder();

    b.source({
      source_type: "external-content",
      location: `source_code:line ${fact.location.line}`,
      observed: fact.location.snippet,
      rationale:
        `Server accept site (${fact.accept_kind}: ${fact.accept_expression}) — ` +
        `any attacker can open a connection and initiate the MCP lifecycle. The ` +
        `MCP spec 2025-03-26 requires clients to send initialize first but does ` +
        `not mandate a server-side deadline.`,
    });

    b.sink({
      sink_type: "network-send",
      location: `source_code:line ${fact.location.line}`,
      observed:
        `${fact.accept_expression} — every accepted connection consumes an FD, a ` +
        `tracking entry, and (for WS/SSE) a heartbeat worker. Without a handshake ` +
        `deadline, half-open connections never free these resources.`,
    });

    b.mitigation({
      mitigation_type: "rate-limit",
      present: false,
      location: fact.location.enclosing_function
        ? `function ${fact.location.enclosing_function}`
        : `module scope near line ${fact.location.line}`,
      detail:
        `No handshakeTimeout/headersTimeout/requestTimeout/AbortSignal.timeout/` +
        `Promise.race/setTimeout present. No maxConnections/backlog/maxClients set. ` +
        `CWE-400 Slowloris-class resource exhaustion is live.`,
    });

    b.impact({
      impact_type: "denial-of-service",
      scope: "server-host",
      exploitability: "trivial",
      scenario:
        `Attacker opens N connections (N ≈ ulimit - 50) and never sends initialize. ` +
        `Each connection holds one server slot until the process restarts. Legitimate ` +
        `clients time out at accept; the server is unreachable within seconds. Identical ` +
        `primitive to Slowloris against HTTP/1.1 servers without per-header timeouts.`,
    });

    b.factor(
      "handshake_deadline_absent",
      0.12,
      `AST-confirmed: ${fact.accept_kind} accept at ${fact.accept_expression}; ` +
        `enclosing scope lacks handshake-timeout, connection-limit vocabulary.`,
    );

    b.reference({
      id: "CWE-400",
      title: "CWE-400 Uncontrolled Resource Consumption",
      url: "https://cwe.mitre.org/data/definitions/400.html",
      relevance:
        "Unbounded connection acceptance without handshake deadline reproduces the Slowloris subclass of CWE-400.",
    });

    b.verification(verifyAcceptWithoutDeadline(fact));
    b.verification(verifyNoMaxConnections(fact));
    b.verification(verifySlowlorisReproducible(fact));

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

registerTypedRuleV2(new N10IncompleteHandshakeDoS());
