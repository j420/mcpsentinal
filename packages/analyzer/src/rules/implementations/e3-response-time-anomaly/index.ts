/**
 * E3 — Response Time Anomaly (v2)
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
import { gatherE3, type LatencyObservation } from "./gather.js";
import {
  stepRepeatMeasurement,
  stepCheckHostMetrics,
  stepCrossRefToolCount,
} from "./verification.js";

const RULE_ID = "E3";
const RULE_NAME = "Response Time Anomaly";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.65;

const REMEDIATION =
  "Investigate the slow tools/list response. Rule out network-side causes first (measure from " +
  "multiple origins). If the slowness is server-side, check for CPU saturation (potential " +
  "cryptojacking), blocked I/O (external API dependency timeout), or excessive payload size " +
  "(reduce tool count — cross-reference E4). Add SLO monitoring on the MCP handshake so future " +
  "latency drift is caught automatically.";

const REF_OWASP_MCP09 = {
  id: "OWASP-MCP09-Logging-Monitoring",
  title: "OWASP MCP Top 10 — MCP09 Insufficient Logging & Monitoring",
  url: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
  relevance:
    "E3 fires as a tripwire for the kind of runtime anomaly MCP09 expects the monitoring stack to " +
    "catch. The presence of an E3 finding is itself an MCP09 indicator: the anomaly is visible to " +
    "a one-shot scanner, suggesting the organisation's continuous monitoring is not catching it.",
} as const;

class ResponseTimeAnomalyRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { connection_metadata: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherE3(context);
    if (!gathered.observation) return [];
    return [this.buildFinding(gathered.observation)];
  }

  private buildFinding(obs: LatencyObservation): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "environment",
        location: obs.capabilityLocation,
        observed:
          `Server took ${obs.responseTimeMs}ms to respond to \`initialize\` + \`tools/list\` ` +
          `(threshold: 10,000ms).`,
        rationale:
          "MCP's initialize + tools/list is a cheap protocol handshake in healthy conditions " +
          "(<1s typical). Sustained 10s+ latency indicates resource abuse (cryptojacker, runaway " +
          "loop), blocked downstream I/O, or degraded runtime (slowloris-class DoS).",
      })
      .sink({
        sink_type: "code-evaluation",
        location: obs.capabilityLocation,
        observed:
          `Whatever is consuming ${obs.responseTimeMs}ms of compute is reachable over the MCP ` +
          `protocol handshake — either the server's own code or a dependency reachable from it.`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: "complex",
        scenario:
          `A sustained >10s latency on protocol handshake degrades the client experience and ` +
          `indicates an unhealthy server. In the cryptojacker sub-case, attacker code is running ` +
          `on the host and siphoning compute. In the slowloris sub-case, the server is approaching ` +
          `starvation and will fail to accept legitimate connections.`,
      })
      .factor(
        "response_time_over_threshold",
        obs.isExtreme ? 0.1 : 0.05,
        `Measured response time ${obs.responseTimeMs}ms exceeds the ` +
          (obs.isExtreme
            ? `EXTREME threshold (30,000ms).`
            : `10,000ms threshold but is below the extreme tier.`),
      );

    builder.reference(REF_OWASP_MCP09);
    builder.verification(stepRepeatMeasurement(obs));
    builder.verification(stepCheckHostMetrics(obs));
    builder.verification(stepCrossRefToolCount(obs));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "low",
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
      `E3 charter caps confidence at ${cap}. Response time is a noisy signal: network-side causes, ` +
      `cold starts, and legitimate large-payload servers all plausibly explain ≥10s latency.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ResponseTimeAnomalyRule());

export { ResponseTimeAnomalyRule };
