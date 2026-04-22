import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherN13, type SmuggleSite } from "./gather.js";
import { N13_CONFIDENCE_CAP } from "./data/n13-config.js";
import {
  buildSmuggleInspectionStep,
  buildDualHeaderStep,
  buildSmuggleFlowStep,
} from "./verification.js";

const RULE_ID = "N13";
const RULE_NAME = "HTTP Chunked Transfer Smuggling";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";

const REMEDIATION =
  "Use a well-tested HTTP library (Node's http/undici, Python stdlib, " +
  "express, fastify) for all Streamable HTTP transport handling. Never " +
  "hand-roll chunked framing. Never set both Transfer-Encoding and " +
  "Content-Length. Reject ambiguous headers at ingress. Review all " +
  "places the code writes raw socket bytes for HTTP framing.";

class ChunkedTransferSmugglingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const g = gatherN13(context);
    if (!g.transport_present) return [];
    if (g.sites.length === 0) return [];
    // Prefer dual-header sites as the worst case
    const worst = g.sites.find((s) => s.dual_headers) ?? g.sites[0];
    return [this.buildFinding(worst, g.safe_stack_present)];
  }

  private buildFinding(site: SmuggleSite, safeStack: boolean): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: site.location,
        observed: site.line_text,
        rationale:
          `HTTP transport code at line ${site.line} uses ${site.smuggle_label}. ` +
          `This is a canonical desync vector from PortSwigger 2019 research, ` +
          `applied here to the Streamable HTTP MCP transport.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: site.location,
        observed:
          `Ambiguous HTTP framing flows end-to-end across intermediaries. ` +
          `Desync between intermediary and backend parsers enables the ` +
          `adversary to splice a second request into the victim's session.`,
      })
      .sink({
        sink_type: "network-send",
        location: site.location,
        observed:
          `Server emits ambiguously-framed bytes; downstream parser ` +
          `consumes past the intended request boundary.`,
        cve_precedent: "CVE-2025-6515",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: safeStack,
        location: site.location,
        detail: safeStack
          ? `Server uses a well-tested HTTP stack marker somewhere in the ` +
            `file. Verify the stack's chunked handling is not bypassed by ` +
            `this specific line.`
          : `No recognised HTTP framework marker in the file. Hand-rolled ` +
            `HTTP framing is almost always a desync vector.`,
      })
      .impact({
        impact_type: "session-hijack",
        scope: "user-data",
        exploitability: "complex",
        scenario:
          `An attacker who can position a request through the same path ` +
          `splices a second JSON-RPC request into the victim's session. ` +
          `The smuggled request runs under the victim's session identity — ` +
          `possibly triggering destructive tool invocations the victim ` +
          `never authorised.`,
      })
      .factor(
        "chunked_framing_manipulated",
        0.12,
        `Line explicitly manipulates chunked framing (${site.smuggle_label}).`,
      )
      .factor(
        site.dual_headers ? "dual_transfer_headers" : "single_transfer_frag",
        site.dual_headers ? 0.08 : 0.0,
        site.dual_headers
          ? `Both Transfer-Encoding and Content-Length present — canonical ` +
            `desync vector.`
          : `Only one smuggling fragment found; still sufficient for ` +
            `raw chunked framing abuse.`,
      )
      .reference({
        id: "CVE-2025-6515",
        title:
          "MCP Streamable HTTP session hijacking (related class: request smuggling)",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6515",
        relevance:
          "N13 extends the CVE-2025-6515 concern surface to HTTP request " +
          "smuggling — a related mechanism for session hijacking.",
      })
      .verification(buildSmuggleInspectionStep(site))
      .verification(buildDualHeaderStep(site))
      .verification(buildSmuggleFlowStep(site));

    const chain = cap(builder.build(), N13_CONFIDENCE_CAP);
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
    rationale: `N13 charter caps confidence at ${v}.`,
  });
  chain.confidence = v;
  return chain;
}

registerTypedRuleV2(new ChunkedTransferSmugglingRule());

export { ChunkedTransferSmugglingRule };
