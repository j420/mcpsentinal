/**
 * E2 — Insecure Transport (HTTP/WS) (v2)
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
import { gatherE2, type InsecureTransportObservation } from "./gather.js";
import {
  stepInspectTransport,
  stepInspectTlsConfig,
  stepCaptureNetworkSample,
} from "./verification.js";

const RULE_ID = "E2";
const RULE_NAME = "Insecure Transport";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Use TLS for all network transports. For HTTP-based MCP servers require https://; for " +
  "WebSocket-based require wss://. Pin TLS 1.2+ (prefer 1.3), disable weak ciphers, and enable " +
  "HSTS. Where a reverse proxy terminates TLS, ensure the inner hop is either mTLS or restricted " +
  "to a private network segment.";

const REF_CWE_319 = {
  id: "CWE-319",
  title: "CWE-319: Cleartext Transmission of Sensitive Information",
  url: "https://cwe.mitre.org/data/definitions/319.html",
  relevance:
    "The canonical CWE for http:// and ws:// transport carrying credentials or sensitive data. " +
    "Any authenticated MCP invocation transmits a session token; any tool call may carry PII or " +
    "credentials in its parameters. CWE-319 applies unambiguously.",
} as const;

class InsecureTransportRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { connection_metadata: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherE2(context);
    if (!gathered.observation) return [];
    return [this.buildFinding(gathered.observation)];
  }

  private buildFinding(obs: InsecureTransportObservation): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: obs.capabilityLocation,
        observed:
          `Live connection to the MCP server used transport "${obs.transport}://" — plaintext.`,
        rationale: obs.spec.rationale,
      })
      .sink({
        sink_type: "credential-exposure",
        location: obs.capabilityLocation,
        observed:
          `All MCP protocol messages transmitted in plaintext. Any authenticated tool invocation ` +
          `leaks its bearer token to network observers; any tool parameter or response leaks to ` +
          `anyone in the network path.`,
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: {
          kind: "config",
          file: "server.config",
          json_pointer: "/tls",
        },
        detail:
          `No TLS termination at the MCP server layer. Expected: ${obs.spec.encrypted_equivalent}:// ` +
          `with TLS 1.2+.`,
      })
      .impact({
        impact_type: "credential-theft",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `Any network attacker in-path (rogue WiFi, compromised router, ISP-level adversary, cloud ` +
          `inter-AZ interception, VPC-internal lateral movement) captures MCP traffic and extracts ` +
          `tokens, API keys, PII, and tool-invocation parameters. Firesheep (2010) proved this on ` +
          `HTTP cookies; the same argument applies to MCP sessions.`,
      })
      .factor(
        "plaintext_transport_observed",
        0.2,
        `Live runtime observation: transport is "${obs.transport}://" (insecure). The scanner ` +
          `connected via plaintext and completed the initialize handshake — no TLS was in the ` +
          `observed path.`,
      );

    builder.reference(REF_CWE_319);
    builder.verification(stepInspectTransport(obs));
    builder.verification(stepInspectTlsConfig(obs));
    builder.verification(stepCaptureNetworkSample(obs));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "high",
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
      `E2 charter caps confidence at ${cap}. Head-room covers intentional test/dev deployments ` +
      `and the rare case of a custom transport label the scanner misinterprets.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new InsecureTransportRule());

export { InsecureTransportRule };
