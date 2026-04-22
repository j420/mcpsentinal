/**
 * J4 — Health Endpoint Information Disclosure (Rule Standard v2).
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
import { gatherJ4, type J4Hit } from "./gather.js";
import { J4_CONFIDENCE_CAP } from "./data/config.js";
import { stepInspectEndpoint, stepCheckAuth } from "./verification.js";

const RULE_ID = "J4";
const RULE_NAME = "Health Endpoint Information Disclosure";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0057";

const REMEDIATION =
  "Strip detailed health/debug/metrics endpoints from production builds. " +
  "If a liveness probe is required, return only 200 OK with no body. " +
  "Require authentication for every detailed diagnostic endpoint. " +
  "Reference CVE-2026-29787 (mcp-memory-service) for the canonical " +
  "exploit precedent.";

class HealthEndpointInfoDisclosureRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const { hits } = gatherJ4(context);
    return hits.map((h) => this.buildFinding(h));
  }

  private buildFinding(hit: J4Hit): RuleResult {
    const loc: Location = {
      kind: "source",
      file: "<server source>",
      line: hit.line_number,
    };
    const severity = hit.spec.severity_tier;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: loc,
        observed: hit.line_preview,
        rationale:
          `Endpoint ${hit.spec.path} typically exposes: ${hit.spec.exposed_info}. ` +
          `Forgotten development diagnostic endpoints are the canonical ` +
          `information-disclosure primitive.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: loc,
        observed: `Endpoint: ${hit.spec.path}`,
        cve_precedent: "CVE-2026-29787",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "server-host",
        exploitability: "trivial",
        scenario:
          "An unauthenticated attacker discovers the endpoint and enumerates " +
          "OS info, database connection strings, memory usage, and " +
          "environment variables. CVE-2026-29787 (mcp-memory-service) " +
          "demonstrated this exact pattern with real-world impact.",
      })
      .factor(
        "health_debug_endpoint_matched",
        0.1,
        `Source references ${hit.spec.path} (${hit.spec.exposed_info}).`,
      )
      .reference({
        id: "CVE-2026-29787",
        title: "mcp-memory-service — unauthenticated /health/detailed info leak",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2026-29787",
        year: 2026,
        relevance:
          "MCP server exposed /health/detailed leaking OS, memory, disk, " +
          "and environment variables without authentication.",
      })
      .verification(stepInspectEndpoint(hit))
      .verification(stepCheckAuth());

    if (hit.fence_hit) {
      builder.factor(
        "false_positive_fence_triggered",
        -0.12,
        "Line contains a fence token (test / mock / example / readme) — " +
          "demoting confidence.",
      );
    }

    const chain = capConfidence(builder.build(), J4_CONFIDENCE_CAP);
    return {
      rule_id: RULE_ID,
      severity,
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
    rationale: `J4 charter caps confidence at ${cap}.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new HealthEndpointInfoDisclosureRule());

export { HealthEndpointInfoDisclosureRule };
