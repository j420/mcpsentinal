/**
 * I15 — Transport Session Security (Rule Standard v2).
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
import { gatherI15, type I15Hit } from "./gather.js";
import { I15_CONFIDENCE_CAP } from "./data/config.js";
import { stepInspectSource, stepCompareCve } from "./verification.js";

const RULE_ID = "I15";
const RULE_NAME = "Transport Session Security";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0061";

const REMEDIATION =
  "Use crypto.randomUUID() for MCP session tokens — never Math.random(), " +
  "Date.now(), or UUID v1. Set secure: true, httpOnly: true, and " +
  "sameSite: 'strict' on session cookies. Rotate tokens on privilege " +
  "elevation and on every client re-init. Refer to the MCP Streamable " +
  "HTTP transport spec (2025-03-26) for the protocol-level expectations " +
  "and CVE-2025-6515 for the real-world precedent.";

class TransportSessionSecurityRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherI15(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: I15Hit): RuleResult {
    const loc: Location = {
      kind: "source",
      file: "<server source>",
      line: hit.line_number,
    };

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: loc,
        observed: hit.line_preview,
        rationale: hit.spec.description,
      })
      .sink({
        sink_type: "credential-exposure",
        location: loc,
        observed: `Anti-pattern kind: ${hit.spec.kind} (${hit.spec.cwe}).`,
        cve_precedent: "CVE-2025-6515",
      })
      .impact({
        impact_type: "session-hijack",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          "Weak session management enables an attacker to predict or steal " +
          "the session token, then impersonate the client — sending tool " +
          "calls and receiving responses as the legitimate user. " +
          "CVE-2025-6515 is the canonical precedent against MCP's " +
          "Streamable HTTP transport.",
      })
      .factor(
        "session_anti_pattern_matched",
        0.1,
        `Matched anti-pattern "${hit.spec_key}" (${hit.spec.cwe}).`,
      )
      .reference({
        id: "CVE-2025-6515",
        title:
          "MCP Streamable HTTP session hijacking via URI manipulation",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6515",
        year: 2025,
        relevance:
          "Demonstrated session hijacking against MCP's Streamable HTTP " +
          "transport layer.",
      })
      .verification(stepInspectSource(hit))
      .verification(stepCompareCve());

    const chain = capConfidence(builder.build(), I15_CONFIDENCE_CAP);
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
    rationale: `I15 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new TransportSessionSecurityRule());

export { TransportSessionSecurityRule };
