/**
 * P10 — Host Network Mode and Missing Egress Controls (v2)
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
import { gatherP10, type P10Hit } from "./gather.js";
import {
  stepInspectNetworkDeclaration,
  stepRecordConfigPointer,
  stepCheckIsolationAlternatives,
  stepCheckLegitimateException,
} from "./verification.js";

const RULE_ID = "P10";
const RULE_NAME = "Host Network Mode and Missing Egress Controls";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "T1557";
const CONFIDENCE_CAP = 0.8;

const REMEDIATION =
  "Never use host network mode for MCP server containers — switch to bridge / " +
  "overlay networks with explicit port mapping. In Kubernetes, set hostNetwork: " +
  "false and apply NetworkPolicy resources to restrict both ingress and egress. " +
  "For legitimate exceptions (CNI plugins, node-exporters, ingress controllers), " +
  "document the justification and apply egress controls (NetworkPolicy / Cilium " +
  "L7 policy) to restrict outbound reach to the metadata service, kubelet API, " +
  "and sibling pod network.";

class HostNetworkModeRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP10(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => {
      const alternatives = gathered.alternativesPerFile.get(hit.file) ?? new Set<string>();
      return this.buildFinding(hit, alternatives);
    });
  }

  private buildFinding(hit: P10Hit, alternatives: Set<string>): RuleResult {
    const hasAlternative = alternatives.size > 0;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `${hit.pattern.description} Host network removes the container's own network ` +
          `namespace; the workload shares the node's routing table, arp cache, and bind ` +
          `address range. Every isolation control Docker / Kubernetes provides at the ` +
          `network layer becomes unreachable.`,
      })
      .sink({
        sink_type: "network-send",
        location: hit.configLocation,
        observed: `Network isolation disabled via ${hit.pattern.id}`,
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: hasAlternative,
        location: hit.configLocation,
        detail: hasAlternative
          ? `Compensating isolation controls present: ${[...alternatives].sort().join(", ")}. ` +
            `Per CHARTER lethal edge case #3, these lower exploitation confidence but do ` +
            `not suppress the finding — hostNetwork still enables ARP / port-bind attacks.`
          : `No compensating isolation controls (NetworkPolicy / bridge / internal) ` +
            `observed in this file.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "connected-services",
        exploitability: "moderate",
        scenario:
          `With the host network namespace, the container can: (1) bind to host ports ` +
          `(e.g. 10255) that bypass the kubelet's authN, (2) reach the cloud metadata ` +
          `service at 169.254.169.254 and steal the node's IAM / instance profile, ` +
          `(3) ARP-spoof the node's mDNS or DNS and impersonate internal services, ` +
          `(4) sniff host network traffic for credentials, JWTs, and session tokens ` +
          `(Unit 42 container-escape research, 2023-2025).`,
      })
      .factor(
        "host_network_mode_detected",
        hit.pattern.weight * 0.1,
        `${hit.pattern.description} at ${hit.file}:${hit.line}.`,
      )
      .factor(
        hasAlternative ? "network_isolation_alternatives_detected" : "no_network_isolation_alternatives",
        hasAlternative ? -0.08 : 0.05,
        hasAlternative
          ? `Alternative isolation controls present in this file: ${[...alternatives].sort().join(", ")}.`
          : `No alternative isolation controls observed.`,
      )
      .factor("variant_form", 0.02, `Matched variant: ${hit.pattern.id}.`)
      .reference({
        id: "CVE-2019-5736",
        title: "runC container escape weaponised via host namespace sharing",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
        relevance:
          "CVE-2019-5736 is the precedent: once a container shares host primitives " +
          "(network or PID), a small in-container foothold pivots to host-root code " +
          "execution. The network variant extends this to cluster-wide lateral " +
          "movement via metadata-service credential theft.",
      })
      .verification(stepInspectNetworkDeclaration(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckIsolationAlternatives(hit, alternatives))
      .verification(stepCheckLegitimateException(hit));

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
      `P10 charter caps confidence at ${cap} — compensating NetworkPolicy and egress ` +
      `controls are often applied out-of-file. A maximum-confidence claim would ` +
      `overstate the evidence.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new HostNetworkModeRule());

export { HostNetworkModeRule };
