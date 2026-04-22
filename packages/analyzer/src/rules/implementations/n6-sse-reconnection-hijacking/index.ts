import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN6, type ReconnectSite } from "./gather.js";
import { N6_CONFIDENCE_CAP } from "./data/sse-surfaces.js";
import {
  buildReconnectInspectionStep,
  buildAuthAbsenceStep,
  buildHijackTraceStep,
} from "./verification.js";

const RULE_ID = "N6";
const RULE_NAME = "SSE Reconnection Hijacking";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0061";

const REMEDIATION =
  "Re-authenticate on every SSE / Streamable-HTTP reconnection. Bind " +
  "Last-Event-ID to session identity via an HMAC signature the server " +
  "verifies on resume. Keep session identifiers OUT of URLs (use Bearer " +
  "tokens in Authorization headers). Reject resumes whose Last-Event-ID " +
  "does not belong to the caller's session.";

class SSEReconnectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN6(context);
    if (g.sites.length === 0) return [];
    // Emit at most one finding per file (architectural).
    const worst = g.sites.find((s) => s.auth_distance === null) ?? g.sites[0];
    return [this.buildFinding(worst)];
  }

  private buildFinding(site: ReconnectSite): RuleResult {
    const authed = site.auth_distance !== null;
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: site.location,
        observed: site.line_text,
        rationale:
          `SSE / Streamable-HTTP transport code at line ${site.line} ` +
          `handles ${site.fragment.label}. Reconnection and session-id ` +
          `paths are the hijack surface per CVE-2025-6515.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Session / event identifier flows from the HTTP layer into ` +
          `application logic without integrity-binding to the original ` +
          `authenticated session.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: site.location,
        observed:
          `Reconnection resumes the stream; the caller gains the ` +
          `victim's stream continuity.`,
        cve_precedent: "CVE-2025-6515",
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: authed,
        location: site.location,
        detail: authed
          ? `Auth fragment "${site.auth_label}" found ${site.auth_distance} ` +
            `line(s) away — confirm coverage of this path.`
          : `No auth / verify / hmac within ±6 lines. Path hijackable.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "user-data",
        exploitability: "moderate",
        scenario:
          `An attacker who observes or brute-forces a Last-Event-ID (leaked ` +
          `in a log, proxy, or ID-prediction-class weakness) replays it to ` +
          `a reconnect endpoint. The server resumes the victim's stream ` +
          `for the attacker — full conversational takeover without any ` +
          `credential.`,
      })
      .factor(
        "reconnect_auth_absent",
        authed ? -0.15 : 0.1,
        authed
          ? `Auth nearby; confirm coverage.`
          : `No auth within window; reconnect authentication absent.`,
      )
      .reference({
        id: "CVE-2025-6515",
        title: "MCP Streamable HTTP session hijacking via URI manipulation",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6515",
        relevance:
          "N6 detects the server-side shape of the CVE-2025-6515 class.",
      })
      .verification(buildReconnectInspectionStep(site))
      .verification(buildAuthAbsenceStep(site))
      .verification(buildHijackTraceStep(site));

    const chain = cap(builder.build(), N6_CONFIDENCE_CAP);
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

function cap(chain: EvidenceChain, v: number): EvidenceChain {
  if (chain.confidence <= v) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: v - chain.confidence,
    rationale: `N6 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new SSEReconnectionRule());

export { SSEReconnectionRule };
