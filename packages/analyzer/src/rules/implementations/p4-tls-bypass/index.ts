/**
 * P4 — TLS Certificate Validation Bypass (v2)
 *
 * One finding per bypass site. Confidence cap 0.85 — dev-only code
 * paths genuinely carry these flags sometimes and the analyzer cannot
 * always distinguish without deeper taint analysis.
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
import { gatherP4, type P4Hit } from "./gather.js";
import {
  stepInspectBypassSite,
  stepRecordConfigPointer,
  stepCheckGlobalScope,
  stepCheckAmplifier,
} from "./verification.js";

const RULE_ID = "P4";
const RULE_NAME = "TLS Certificate Validation Bypass";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove the TLS-bypass pattern. Fix the underlying trust issue instead: (1) " +
  "for internal CAs, pin the CA bundle via NODE_EXTRA_CA_CERTS (Node) / " +
  "requests.Session(verify=\"/path/ca.pem\") (Python) / tls.Config{RootCAs:} (Go) / " +
  "CustomTrustManager (Java); (2) for development convenience, use a real " +
  "development certificate via mkcert or the project's internal PKI; (3) for " +
  "CI mirrors, configure the CI environment with the correct CA bundle, do not " +
  "bypass. Never set NODE_TLS_REJECT_UNAUTHORIZED=0 — it affects every downstream " +
  "HTTPS call in the process.";

class TLSBypassRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP4(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P4Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale: hit.pattern.description,
      })
      .sink({
        sink_type: "config-modification",
        location: hit.configLocation,
        observed: `${hit.pattern.id} — outbound HTTPS call proceeds without certificate validation.`,
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: hit.pattern.globalScope ? "connected-services" : "user-data",
        exploitability: "moderate",
        scenario:
          `An attacker positioned between the MCP server and its upstream HTTPS ` +
          `peer (shared Wi-Fi, compromised upstream router, ARP spoof on the pod ` +
          `network, transparent-proxy MITM) intercepts traffic. Because ` +
          `certificate validation is disabled, the MITM certificate is accepted. ` +
          `Credentials, session tokens, and API payloads in transit are captured. ` +
          `${hit.pattern.globalScope ? "This bypass is PROCESS-WIDE — every HTTPS library in the MCP server is affected." : "This specific call / agent is affected; other calls may still verify."}`,
      })
      .factor(
        "bypass_variant",
        hit.pattern.weight * 0.1,
        `Bypass variant: ${hit.pattern.id} (${hit.pattern.language}).`,
      )
      .factor(
        "language_family",
        0.02,
        `Language family: ${hit.pattern.language}.`,
      )
      .factor(
        "global_scope_impact",
        hit.pattern.globalScope ? 0.08 : 0.0,
        hit.pattern.globalScope
          ? `Global-scope override — every downstream HTTPS call in the process.`
          : `Local-scope override — limited to this call / agent instance.`,
      )
      .factor(
        "amplifier_present",
        hit.amplifierPresent ? 0.05 : 0.0,
        hit.amplifierPresent
          ? `Warning-suppression amplifier present — intentional silent bypass.`
          : `No warning-suppression amplifier — accidental bypass is possible.`,
      )
      .reference({
        id: "CWE-295",
        title: "CWE-295 — Improper Certificate Validation",
        url: "https://cwe.mitre.org/data/definitions/295.html",
        relevance:
          "CWE-295 explicitly names the Node.js rejectUnauthorized:false, Python " +
          "requests verify=False, and Go InsecureSkipVerify:true patterns as the " +
          "canonical realisations of this weakness. Any outbound HTTPS call on a " +
          "compromised network becomes an exfiltration channel.",
      })
      .verification(stepInspectBypassSite(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckGlobalScope(hit))
      .verification(stepCheckAmplifier(hit));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

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

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P4 charter caps confidence at ${cap} — dev-only / test-only code paths ` +
      `occasionally carry these flags. A maximum-confidence claim would overstate ` +
      `the evidence without deeper taint analysis.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new TLSBypassRule());

export { TLSBypassRule };
