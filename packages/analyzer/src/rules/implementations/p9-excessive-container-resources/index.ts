/**
 * P9 — Missing / Excessive Container Resource Limits (v2)
 *
 * One finding per RESOURCE_KEY match. Confidence cap 0.75 — namespace-
 * level LimitRange / ResourceQuota / daemon-default ulimits can all
 * supply compensating defaults the analyzer cannot observe.
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
import { gatherP9, type P9FlagHit } from "./gather.js";
import type { ResourceKind } from "./data/resource-flags.js";
import {
  stepInspectResourceDeclaration,
  stepRecordConfigPointer,
  stepCheckRequestsPresence,
  stepCheckNamespaceLimitRange,
} from "./verification.js";

const RULE_ID = "P9";
const RULE_NAME = "Missing Container Resource Limits";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "T1499.001";
const CONFIDENCE_CAP = 0.75;

const REMEDIATION =
  "Set resource limits for every MCP server container: `resources.limits.{cpu,memory}` " +
  "in Kubernetes, `memory` / `cpus` / `pids_limit` in docker-compose, and " +
  "`--memory`, `--cpus`, `--pids-limit`, `--ulimit nofile=1024:2048` on Docker CLI. " +
  "Set BOTH requests AND limits — requests-only leaves the container free to consume " +
  "past its bin-packed neighbours. Apply a namespace LimitRange + ResourceQuota as " +
  "defense-in-depth. Never use the unlimited sentinels (-1, 0, unlimited). For PIDs, " +
  "set pids.max in cgroups — default kernel limits are inadequate for container " +
  "fork-bomb mitigation.";

class ExcessiveContainerResourcesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP9(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => {
      const requests = gathered.requestsPerFile.get(hit.file);
      const requestsForKind = requests?.has(hit.rule.kind) ?? false;
      return this.buildFinding(hit, requestsForKind);
    });
  }

  private buildFinding(hit: P9FlagHit, requestsForKind: boolean): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `${hit.rule.description} ${describeDoSPrimitive(hit.rule.kind)} The spec ` +
          `declares a resource contract that a malicious or runaway workload can ` +
          `weaponise, either against itself (OOM-kill thrash) or against co-located ` +
          `containers on the same host (resource steal).`,
      })
      .sink({
        sink_type: "config-modification",
        location: hit.configLocation,
        observed: `Resource-limit gap: ${hit.rule.description}`,
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: requestsForKind,
        location: hit.configLocation,
        detail: requestsForKind
          ? `${hit.rule.kind} requests ARE present in this file. Per CHARTER lethal ` +
            `edge case #1, this is a materially worse failure mode than "no resources ` +
            `block" — the scheduler packs the pod believing requests represent usage.`
          : `No ${hit.rule.kind} requests observed either — full gap.`,
      })
      .impact({
        impact_type: "denial-of-service",
        scope: "server-host",
        exploitability: hit.rule.kind === "pids" ? "trivial" : "moderate",
        scenario: buildImpactScenario(hit),
      })
      .factor(
        "missing_or_excessive_limit",
        hit.rule.weight * 0.1,
        `${hit.rule.matchKind === "excessive-value" ? "Excessive" : "Unlimited"} ${hit.rule.kind} at ${hit.file}:${hit.line}.`,
      )
      .factor("resource_kind", 0.02, `Resource kind: ${hit.rule.kind}`)
      .factor(
        requestsForKind ? "compensating_requests_present_but_no_limits" : "compensating_requests_absent",
        requestsForKind ? 0.04 : 0.02,
        requestsForKind
          ? `Requests are set without corresponding limits — worsens the failure mode.`
          : `Neither requests nor limits — baseline gap.`,
      )
      .reference({
        id: "CVE-2017-16995",
        title: "Linux kernel eBPF — fork-bomb amplifier precedent",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2017-16995",
        relevance:
          "Missing PID limits turn a small in-container foothold into a host-wide " +
          "PID exhaustion DoS. The kernel's default PID ceiling (32768) is shared " +
          "across all co-located containers.",
      })
      .verification(stepInspectResourceDeclaration(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckRequestsPresence(hit, requestsForKind))
      .verification(stepCheckNamespaceLimitRange(hit));

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

function describeDoSPrimitive(kind: ResourceKind): string {
  switch (kind) {
    case "memory":
      return "Unbounded memory growth triggers the host OOM-killer; co-located containers are killed before the runaway container.";
    case "cpu":
      return "Unbounded CPU consumption creates a noisy-neighbour — the offending container starves every other workload on the node.";
    case "pids":
      return "Unbounded PID count enables a fork-bomb — the container fills the kernel PID namespace and the kubelet cannot reconcile.";
    case "ulimit-nofile":
      return "Unbounded file-descriptor use exhausts the host's nofile ceiling and denies service to the socket-accepting processes.";
  }
}

function buildImpactScenario(hit: P9FlagHit): string {
  switch (hit.rule.kind) {
    case "memory":
      return (
        `A single malicious tool invocation allocates until the OOM-killer fires. ` +
        `The killer selects victims by oom_score_adj — co-located pods with positive ` +
        `score adjustments die first. The offending container re-starts under the ` +
        `same spec and repeats.`
      );
    case "cpu":
      return (
        `A tight loop in the MCP server steals every CPU slice on the node. Liveness ` +
        `probes on sibling pods time out; the kubelet marks them unhealthy and restarts ` +
        `them, amplifying the DoS.`
      );
    case "pids":
      return (
        `\`while true; do :& done\` in a shell inside the container exhausts the node's ` +
        `PID ceiling in seconds. Every subsequent fork on the host fails — including ` +
        `kubelet reconciles and sshd, requiring a node reboot.`
      );
    case "ulimit-nofile":
      return (
        `A connection-leak bug fills the host's fd ceiling. Socket() calls start ` +
        `failing cluster-wide; the control plane cannot accept new connections and ` +
        `drift detection stops.`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P9 charter caps confidence at ${cap} — namespace LimitRange / ResourceQuota / ` +
      `Docker daemon default-ulimits routinely supply compensating defaults that the ` +
      `analyzer cannot observe from source.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new ExcessiveContainerResourcesRule());

export { ExcessiveContainerResourcesRule };
