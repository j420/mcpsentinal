/**
 * Q3 — Localhost MCP Service Hijacking (Rule Standard v2).
 *
 * Honest refusal: skips when no listener call is found in the
 * source. Confidence cap 0.75 (localhost binds in non-MCP health
 * endpoints are a legitimate FP class).
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
import { gatherQ3, type LocalhostBindSite } from "./gather.js";
import { stepInspectBind, stepCheckAuth } from "./verification.js";

const RULE_ID = "Q3";
const RULE_NAME = "Localhost MCP Service Hijacking";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.75;

const REMEDIATION =
  "Add mutual authentication to every localhost MCP listener. The " +
  "server must require a per-session bearer token or shared secret " +
  "on every request. For purely local deployments prefer a unix " +
  "domain socket with filesystem permissions over a TCP port. DNS " +
  "rebinding attacks can reach 127.0.0.1 services, so localhost is " +
  "NOT a security boundary. Also implement an Origin-header check " +
  "on WebSocket transports.";

const STRATEGY_SHARED_VOCAB = "shared-localhost-sinks-vocabulary";
const STRATEGY_LISTEN_BIND = "listen-bind-ast-match";
const STRATEGY_AUTH_SUPPRESS = "auth-token-scope-suppression";
const STRATEGY_SKIP_NO_NET = "skip-when-no-network-binding";

class LocalhostHijackingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  readonly edgeCaseStrategies = [
    STRATEGY_SHARED_VOCAB,
    STRATEGY_LISTEN_BIND,
    STRATEGY_AUTH_SUPPRESS,
    STRATEGY_SKIP_NO_NET,
  ] as const;

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherQ3(context);
    if (gathered.noNetworkBinding) return [];
    const out: RuleResult[] = [];
    for (const site of gathered.sites) {
      if (site.enclosingHasAuth) continue;
      out.push(this.buildFinding(site));
    }
    return out.slice(0, 10);
  }

  private buildFinding(site: LocalhostBindSite): RuleResult {
    const chain = this.buildChain(site);
    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildChain(site: LocalhostBindSite): EvidenceChain {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: site.location,
        observed: site.observed,
        rationale:
          `A listener bound to "${site.host}" exposes the MCP tool ` +
          `surface to every process running as the user AND to any ` +
          `website that can exploit DNS rebinding. Absent auth, the ` +
          `full tool set is callable.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Listener handler receives requests from any source that ` +
          `reaches the loopback port.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed: `Unauthenticated localhost bind at ${site.host}.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: site.mcpTokenOnReceiver ? "trivial" : "moderate",
        scenario:
          `A local attacker or DNS-rebinding website enumerates tools ` +
          `via tools/list and invokes any of them — filesystem reads, ` +
          `code execution, credential access — without presenting any ` +
          `credential the MCP server checks.`,
      })
      .factor(
        "localhost_bind_observed",
        0.14,
        `AST match: .listen / .bind to ${site.host} ` +
          `(${STRATEGY_LISTEN_BIND} / ${STRATEGY_SHARED_VOCAB}).`,
      )
      .factor(
        "no_auth_in_scope",
        0.08,
        `No authorization / bearer / sharedSecret identifier in the ` +
          `enclosing function — ${STRATEGY_AUTH_SUPPRESS} did not demote.`,
      );

    if (site.mcpTokenOnReceiver) {
      builder.factor(
        "mcp_token_on_receiver",
        0.05,
        `Receiver chain mentions an MCP token — the bound service is ` +
          `strongly attributable to MCP.`,
      );
    }

    builder.reference({
      id: "DNS-REBINDING-PRIMER",
      title: "PortSwigger — DNS rebinding primer",
      url: "https://portswigger.net/research/dns-rebinding-attacks",
      relevance:
        "Explains how a website can reach a localhost service after " +
        "TTL expiry; applies directly to unauthenticated localhost " +
        "MCP listeners.",
    });

    builder.verification(stepInspectBind(site));
    builder.verification(stepCheckAuth(site));

    const chain = builder.build();
    return capConfidence(chain, CONFIDENCE_CAP);
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `Q3 charter caps confidence at ${cap}. A localhost bind with ` +
      `no visible auth middleware may still validate inside the ` +
      `route handler; static analysis cannot exhaustively prove the ` +
      `negative.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new LocalhostHijackingRule());

export { LocalhostHijackingRule };
