/**
 * E1 — No Authentication Required (v2)
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
import { gatherE1, type NoAuthObservation } from "./gather.js";
import {
  stepAttemptUnauthenticated,
  stepCheckReverseProxy,
  stepCheckBindAddress,
} from "./verification.js";

const RULE_ID = "E1";
const RULE_NAME = "No Authentication Required";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Require authentication for all MCP server connections. For remote MCP servers adopt OAuth 2.0 " +
  "per RFC 9700 / the MCP Authorization specification. For stdio-launched servers rely on the " +
  "parent process's security boundary and DO NOT expose the same server over network transports. " +
  "Even localhost-bound servers should require auth: DNS rebinding (CCS 2007) makes localhost " +
  "reachable from any browser tab.";

const REF_MCP_AUTHZ = {
  id: "MCP-Authorization-2025",
  title: "MCP Authorization Specification (mid-2025 adoption)",
  url: "https://modelcontextprotocol.io/docs/concepts/authorization",
  relevance:
    "The MCP Authorization spec requires OAuth 2.0 (RFC 9700) or equivalent for remote servers. " +
    "A server that serves initialize + tools/list unauthenticated is out of spec conformance.",
} as const;

class NoAuthenticationRequiredRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { connection_metadata: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherE1(context);
    if (!gathered.observation) return [];
    return [this.buildFinding(gathered.observation)];
  }

  private buildFinding(obs: NoAuthObservation): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: obs.capabilityLocation,
        observed:
          `Live connection to the MCP server over ${obs.transport} succeeded with no credentials. ` +
          `\`initialize\` + \`tools/list\` returned without any WWW-Authenticate challenge.`,
        rationale:
          "An MCP server that answers tool enumeration without authentication trusts the network. " +
          "Under modern threat models (CCS 2007 DNS rebinding, open cloud networking) no network " +
          "is trustworthy.",
      })
      .sink({
        sink_type: "privilege-grant",
        location: obs.capabilityLocation,
        observed:
          `Full tool authority exposed without identity verification. Any client that reaches the ` +
          `transport can enumerate and (on systems that expose invocation) call every tool.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: obs.capabilityLocation,
        detail:
          "No authentication mechanism present at the MCP server layer. Reverse-proxy-terminated " +
          "auth may exist at a layer the scanner cannot observe; reviewer must confirm via the " +
          "deployment diagram.",
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          "Any network-reachable client can connect and invoke tools with the server's delegated " +
          "authority. For localhost-bound servers, a malicious web page can still reach the server " +
          "via DNS rebinding (Jackson/Bortz/Boneh 2007), making localhost no better than 0.0.0.0.",
      })
      .factor(
        "no_auth_confirmed_runtime",
        0.2,
        `Live runtime observation: connection over ${obs.transport} succeeded without credentials. ` +
          `This is not a heuristic — the scanner demonstrated the unauth posture directly.`,
      );

    builder.reference(REF_MCP_AUTHZ);
    builder.verification(stepAttemptUnauthenticated(obs));
    builder.verification(stepCheckReverseProxy(obs));
    builder.verification(stepCheckBindAddress(obs));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "medium",
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
      `E1 charter caps confidence at ${cap}. The head-room covers reverse-proxy-terminated auth ` +
      `the scanner cannot see, and the intentional-unauth case (public read-only registries).`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new NoAuthenticationRequiredRule());

export { NoAuthenticationRequiredRule };
