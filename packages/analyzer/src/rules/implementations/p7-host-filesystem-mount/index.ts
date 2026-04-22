/**
 * P7 — Sensitive Host Filesystem Mount (v2)
 *
 * One finding per mount site. Confidence cap 0.85 — namespace-level
 * admission controllers, seccomp / AppArmor, and read-only flags
 * partially reduce exploit reach.
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
import { gatherP7, type P7Hit } from "./gather.js";
import {
  stepInspectHostMount,
  stepRecordConfigPointer,
  stepCheckReadOnlyClaim,
  stepCheckNarrowerAlternative,
} from "./verification.js";

const RULE_ID = "P7";
const RULE_NAME = "Sensitive Host Filesystem Mount";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove the sensitive host-path mount or narrow it to the smallest directory " +
  "that satisfies the workload's need. Migrate to ConfigMap / Secret / emptyDir / " +
  "projected / CSI volume types — all are accepted by Kubernetes Pod Security " +
  "Standards Restricted. For workloads that legitimately need host access " +
  "(node-exporter, CNI, log collector), (1) scope the hostPath to the minimum " +
  "required subtree, (2) set readOnly: true (reduces but does not eliminate the " +
  "gap), (3) annotate the namespace with an explicit exception, (4) pin the " +
  "workload to dedicated nodes where cross-tenant blast radius is bounded. " +
  "Read-only is NOT a mitigation for sensitive files — SSH host keys, shadow, " +
  "kubelet credentials, and TLS material are all readable regardless of rw flag.";

class HostFilesystemMountRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP7(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P7Hit): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale:
          `${hit.spec.description} Mounting this path bypasses container filesystem ` +
          `isolation and makes the node's sensitive files readable (and often ` +
          `writable) from inside the container.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: hit.configLocation,
        observed:
          `${hit.spec.path} bound as a volume in context "${hit.mountContext}". ` +
          `Container filesystem gains a view of the host subtree — ${hit.readonlyFlag ? "read-only, " : ""}` +
          `every file readable by the container user is reachable.`,
      })
      .sink({
        sink_type: "credential-exposure",
        location: hit.configLocation,
        observed:
          `Container reads (and optionally writes) ${hit.spec.path} — ` +
          `${hit.spec.category === "kubelet-credentials" ? "kubelet impersonation primitive" : hit.spec.category === "ssh-keys" ? "SSH key theft" : hit.spec.category === "kube-config" ? "cluster admin credential theft" : "sensitive-file exposure"}.`,
        cve_precedent: hit.spec.isRootFilesystem ? "CVE-2019-5736" : undefined,
      })
      .impact({
        impact_type: hit.spec.isRootFilesystem ? "remote-code-execution" : "credential-theft",
        scope: "server-host",
        exploitability: hit.spec.isRootFilesystem ? "trivial" : "moderate",
        scenario: buildImpactScenario(hit),
      })
      .factor(
        "host_path_variant",
        hit.spec.weight * 0.1,
        `Sensitive-path variant: ${hit.spec.id} (${hit.spec.category}).`,
      )
      .factor(
        "mount_context",
        0.04,
        `Mount context token: ${hit.mountContext}.`,
      )
      .factor(
        "readonly_flag_present",
        hit.readonlyFlag ? -0.05 : 0,
        hit.readonlyFlag
          ? `Read-only flag present — reduces (but does not eliminate) the gap. ` +
            `Sensitive files (SSH keys, shadow, kubelet credentials) are still ` +
            `readable, so the finding stands; the flag gets a small negative ` +
            `confidence adjustment.`
          : `No read-only flag — full read/write access.`,
      )
      .reference({
        id: "CVE-2019-5736",
        title: "runC container escape via /proc/self/exe overwrite",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
        relevance:
          "CVE-2019-5736 weaponises a writable host primitive for container escape. " +
          "Host filesystem mounts (especially /, /proc, /dev) supply exactly the " +
          "primitive the exploit needs. Even narrower mounts (/etc, /var/run, " +
          "/var/lib/kubelet) grant credential-theft primitives that compound with " +
          "any other container-escape vulnerability.",
      })
      .verification(stepInspectHostMount(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckReadOnlyClaim(hit))
      .verification(stepCheckNarrowerAlternative(hit));

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

function buildImpactScenario(hit: P7Hit): string {
  switch (hit.spec.category) {
    case "root":
      return (
        `Full host root inside the container. Attacker reads /etc/shadow, /root/.ssh, ` +
        `every file the host can see; writes /etc/ld.so.preload, /root/.ssh/authorized_keys, ` +
        `or /proc/sysrq-trigger; and weaponises CVE-2019-5736 for /proc/self/exe overwrite ` +
        `to obtain host-root code execution.`
      );
    case "etc":
      return (
        `Exposes systemd unit files, kubeconfig, SSH host keys, /etc/shadow. Attacker ` +
        `reads every trust anchor the host uses and forges tokens / SSH sessions.`
      );
    case "var-run":
      return (
        `Contains the Docker / containerd / podman socket plus kubelet pid / unix sockets. ` +
        `Mounting /var/run is equivalent to mounting the runtime socket directly — ` +
        `see P1 for the container-escape chain.`
      );
    case "kubelet-credentials":
      return (
        `Reads kubelet PKI and service-account tokens. Attacker impersonates the node's ` +
        `kubelet and enumerates every secret the node can see cluster-wide.`
      );
    case "ssh-keys":
      return (
        `Reveals SSH private keys. Attacker authenticates to every upstream SSH target ` +
        `that trusts the key.`
      );
    case "kube-config":
      return (
        `Exposes cluster admin / user kubeconfig. Attacker gains cluster-admin or ` +
        `user-scoped API access and pivots to every namespace.`
      );
    case "proc":
      return (
        `Process memory space of every host process — readable keys, tokens, and ` +
        `in-memory secrets.`
      );
    case "sys":
      return (
        `Kernel subsystems, cgroup controllers, unprivileged-user-namespace toggles ` +
        `— pivot primitives for container escape.`
      );
    case "dev":
      return (
        `Raw block / character devices — attacker reads disks, writes to terminals, ` +
        `pivots to host console.`
      );
    case "root-home":
      return (
        `Root user home directory — history, SSH keys, previously-used credentials.`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P7 charter caps confidence at ${cap} — namespace-level admission rules, ` +
      `seccomp / AppArmor, and read-only flags reduce exploit reach.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new HostFilesystemMountRule());

export { HostFilesystemMountRule };
