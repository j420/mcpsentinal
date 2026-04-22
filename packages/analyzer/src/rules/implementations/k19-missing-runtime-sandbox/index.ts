/**
 * K19 — Missing Runtime Sandbox Enforcement (v2)
 *
 * Orchestrator. Consumes K19 gatherer facts (one per matched sandbox-disable
 * flag) and turns each into an EvidenceChain. One finding per hit —
 * privileged-mode + hostPID is two separate CIS §5.2 failures, each with
 * its own audit-evidence requirement.
 *
 * Confidence cap: 0.85. Admission-controller mutations / Kyverno / OPA
 * Gatekeeper are out-of-file and may downgrade the finding at runtime.
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
import { gatherK19, type K19FlagHit } from "./gather.js";
import {
  stepInspectDisableFlag,
  stepRecordConfigPointer,
  stepInspectCompensatingControls,
  stepCheckAdmissionControl,
} from "./verification.js";

const RULE_ID = "K19";
const RULE_NAME = "Missing Runtime Sandbox Enforcement";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Enforce container sandboxing: never run containers with `privileged: true`, never " +
  "share host namespaces (hostPID / hostIPC / hostNetwork), keep seccomp at " +
  "RuntimeDefault (never Unconfined), AppArmor at runtime/default, set `runAsNonRoot: " +
  "true` + `allowPrivilegeEscalation: false` + `readOnlyRootFilesystem: true`, and " +
  "drop ALL capabilities (then add back only the exact ones needed). Enforce Pod " +
  "Security Admission baseline at the namespace level. For Docker, use `userns-remap` " +
  "and never `--cap-add=ALL`.";

class MissingRuntimeSandboxRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK19(context);
    if (gathered.hits.length === 0) return [];

    return gathered.hits.map((hit) => {
      const compensations = gathered.compensationPerFile.get(hit.file) ?? new Set<string>();
      return this.buildFinding(hit, compensations);
    });
  }

  private buildFinding(hit: K19FlagHit, compensations: Set<string>): RuleResult {
    const hasAnyCompensation = compensations.size > 0;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `${hit.flag.description} This breaks container isolation at the kernel level — ` +
          `a ${hit.flag.category} defeat in the source-of-truth configuration. Remediation ` +
          `per CIS Kubernetes Baseline §5.2 is non-optional for multi-tenant clusters.`,
      })
      .sink({
        sink_type: "privilege-grant",
        location: hit.configLocation,
        observed:
          `Sandbox boundary removed: ${hit.flag.category} via ${hit.flag.key}` +
          (hit.capabilityMatched ? ` (capability ${hit.capabilityMatched})` : ""),
        cve_precedent: hit.flag.cveReference,
      })
      .mitigation({
        mitigation_type: "sandbox",
        present: hasAnyCompensation,
        location: hit.configLocation,
        detail: hasAnyCompensation
          ? `Compensating controls present in the same file: ${[...compensations].sort().join(", ")}. ` +
            `Per CHARTER lethal edge case #1, compensations do not suppress a ${hit.flag.category} ` +
            `finding — privileged mode neutralises runAsNonRoot at runtime.`
          : `No compensating controls (runAsNonRoot, readOnlyRootFilesystem, no-new-privileges) ` +
            `observed in this file — full sandbox defeat.`,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: "server-host",
        exploitability: hit.flag.weight >= 0.9 ? "trivial" : "moderate",
        scenario: buildImpactScenario(hit),
      })
      .factor(
        "sandbox_disable_flag_found",
        hit.flag.weight * 0.12,
        `Matched flag "${hit.flag.key}" at ${hit.file}:${hit.line}. ${hit.flag.description}`,
      )
      .factor(
        hasAnyCompensation ? "compensating_controls_detected" : "no_compensating_controls",
        hasAnyCompensation ? -0.1 : 0.05,
        hasAnyCompensation
          ? `Compensating controls present: ${[...compensations].sort().join(", ")}. Lowers ` +
            `exploitation confidence but does not suppress the ${hit.flag.category} finding.`
          : `No compensating securityContext keys observed in this file.`,
      )
      .factor(
        "flag_category",
        0.02,
        `CIS §5.2 subcategory: ${hit.flag.category}. Remediation references ${hit.flag.description}`,
      )
      .reference(buildThreatReference(hit))
      .verification(stepInspectDisableFlag(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepInspectCompensatingControls(hit, compensations))
      .verification(stepCheckAdmissionControl(hit));

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

function buildImpactScenario(hit: K19FlagHit): string {
  const base =
    `${hit.flag.description} combined with a minimal in-container foothold yields ` +
    `host-root in a single syscall — `;
  switch (hit.flag.category) {
    case "privileged-mode":
      return (
        base +
        `an attacker with any shell in the container can run \`mount -t cgroup\` and write ` +
        `to release_agent (CVE-2022-0492), or overwrite the runC init binary (CVE-2019-5736) ` +
        `to take host root on the next exec.`
      );
    case "capability-addition":
      return (
        base +
        `CAP_SYS_ADMIN alone enables user-namespace creation and fsconfig syscalls ` +
        `(CVE-2022-0185), giving an attacker kernel-heap primitives sufficient for host ` +
        `root without requiring privileged mode.`
      );
    case "security-profile-disable":
      return (
        base +
        `with seccomp/AppArmor disabled every syscall the kernel exposes is reachable; ` +
        `pivot_root/mount/chroot become available for container escape via release_agent ` +
        `or eBPF (CVE-2022-0492 class).`
      );
    case "host-namespace-share":
      return (
        base +
        `hostPID makes /proc/1/environ and /proc/1/root visible — the attacker reads ` +
        `every other container's environment variables (API keys, JWTs, KMS secrets) ` +
        `and can ptrace-attach to the Kubelet or node agent for full-node takeover.`
      );
    case "privilege-escalation":
      return (
        base +
        `allowPrivilegeEscalation lets an unprivileged process gain root via any setuid ` +
        `binary on the image — the attacker only needs to land file-write to plant one.`
      );
  }
}

function buildThreatReference(hit: K19FlagHit): {
  id: string;
  title: string;
  url?: string;
  relevance: string;
} {
  if (hit.flag.cveReference === "CVE-2019-5736") {
    return {
      id: "CVE-2019-5736",
      title: "runC container escape via /proc/self/exe",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
      relevance:
        "Host PID namespace / privileged mode provides the primitives needed to overwrite " +
        "the host runC binary, escalating a foothold in the container to root on the host.",
    };
  }
  if (hit.flag.cveReference === "CVE-2022-0492") {
    return {
      id: "CVE-2022-0492",
      title: "Linux cgroup v1 release_agent container escape",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
      relevance:
        "Privileged mode or explicit CAP_SYS_ADMIN allows unprivileged writes to " +
        "release_agent, giving root code execution on the host via kernel-invoked helper.",
    };
  }
  // Default for capability-addition without explicit CVE on the flag — still citing
  // CVE-2022-0185 (fsconfig) as the capability-weaponisation precedent.
  if (hit.flag.category === "capability-addition") {
    return {
      id: "CVE-2022-0185",
      title: "Linux fsconfig heap overflow — weaponised via CAP_SYS_ADMIN",
      url: "https://nvd.nist.gov/vuln/detail/CVE-2022-0185",
      relevance:
        "Adding CAP_SYS_ADMIN (or ALL) to an unprivileged container gives the attacker " +
        "the syscall surface required to weaponise fsconfig into host root.",
    };
  }
  return {
    id: "CIS-Kubernetes-5.2",
    title: "CIS Kubernetes Benchmark §5.2 Pod Security Standards — Baseline",
    url: "https://www.cisecurity.org/benchmark/kubernetes",
    relevance:
      "The flagged configuration violates the CIS Baseline pod security standard that is " +
      "the minimum acceptable posture for multi-tenant clusters.",
  };
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K19 charter caps confidence at ${cap} — admission controllers (PSA baseline, ` +
      `Kyverno, OPA Gatekeeper) can reject or mutate this setting at apply time. ` +
      `Static analysis cannot observe those controls, so claiming maximum confidence ` +
      `would overstate the evidence.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new MissingRuntimeSandboxRule());

export { MissingRuntimeSandboxRule };
