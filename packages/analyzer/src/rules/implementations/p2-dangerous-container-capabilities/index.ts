/**
 * P2 — Dangerous Container Capabilities & Privileged Mode (v2)
 *
 * One finding per distinct declaration. Confidence cap 0.85 — seccomp /
 * AppArmor / user-namespace-remap profiles can partially defeat
 * exploitation but the analyzer cannot observe them from YAML.
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
import { gatherP2, type P2Hit } from "./gather.js";
import {
  stepInspectCapabilityDeclaration,
  stepRecordConfigPointer,
  stepCheckDropAllCompanion,
  stepCheckSeccompAppArmor,
} from "./verification.js";

const RULE_ID = "P2";
const RULE_NAME = "Dangerous Container Capabilities & Privileged Mode";
const OWASP = "MCP07-insecure-config" as const;
const MITRE = "AML.T0054";
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Remove privileged: true and any dangerous capability adds (SYS_ADMIN, " +
  "SYS_MODULE, SYS_PTRACE, NET_ADMIN, DAC_OVERRIDE, DAC_READ_SEARCH, SETUID, " +
  "SETGID, ALL). Use `cap_drop: [ALL]` with a minimal, justified `cap_add` " +
  "list — NET_BIND_SERVICE is the only capability the Kubernetes PSS " +
  "Restricted profile permits by default. Remove hostPID / hostIPC / " +
  "hostNetwork / hostUsers: false — each shares a separate host namespace " +
  "and must be justified independently. Pair with a RuntimeDefault seccomp " +
  "profile and a Localhost AppArmor profile for defense-in-depth.";

class DangerousCapabilitiesRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherP2(context);
    if (gathered.hits.length === 0) return [];
    return gathered.hits.map((hit) => this.buildFinding(hit));
  }

  private buildFinding(hit: P2Hit): RuleResult {
    const isCapability = hit.kind === "capability";
    const impactScope = hit.kind === "namespace" ? "connected-services" : "server-host";
    const exploitability =
      (isCapability && (hit.spec.kind === "mount-escape" || hit.spec.kind === "all-capabilities")) ||
      (hit.kind === "namespace" && hit.spec.id === "privileged")
        ? "trivial"
        : "moderate";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: hit.location,
        observed: hit.observed,
        rationale: hit.spec.description,
      })
      .sink({
        sink_type: "privilege-grant",
        location: hit.configLocation,
        observed: isCapability
          ? `Capability CAP_${hit.spec.name} added — unlocks ${hit.spec.kind} primitive.`
          : `Host namespace / privileged-mode declaration — ${hit.spec.id}.`,
        cve_precedent: isCapability && hit.spec.name === "SYS_ADMIN" ? "CVE-2022-0185" : undefined,
      })
      .impact({
        impact_type: "privilege-escalation",
        scope: impactScope,
        exploitability,
        scenario: buildImpactScenario(hit),
      })
      .factor(
        "capability_variant",
        hit.spec.weight * 0.1,
        isCapability
          ? `Capability: CAP_${hit.spec.name} (${hit.spec.kind}).`
          : `Namespace/privileged variant: ${hit.spec.id}.`,
      )
      .factor(
        "declaration_site",
        0.03,
        isCapability
          ? `Capability context: ${hit.context}.`
          : `Top-level securityContext / pod-level declaration.`,
      )
      .factor(
        "drop_all_companion",
        isCapability && hit.dropAllCompanion ? 0.02 : 0,
        isCapability && hit.dropAllCompanion
          ? `cap_drop: ALL present alongside the add — the add still applies, per ` +
            `charter lethal edge #2. Slight positive adjustment because operators ` +
            `often mistake this for a mitigation.`
          : `No drop-all companion observed.`,
      )
      .reference({
        id: isCapability && hit.spec.name === "SYS_ADMIN" ? "CVE-2022-0185" : "CVE-2022-0492",
        title:
          isCapability && hit.spec.name === "SYS_ADMIN"
            ? "Linux kernel fsconfig heap overflow weaponised via CAP_SYS_ADMIN"
            : "Linux cgroup v1 release_agent container escape via CAP_SYS_ADMIN",
        url:
          isCapability && hit.spec.name === "SYS_ADMIN"
            ? "https://nvd.nist.gov/vuln/detail/CVE-2022-0185"
            : "https://nvd.nist.gov/vuln/detail/CVE-2022-0492",
        relevance:
          isCapability && hit.spec.name === "SYS_ADMIN"
            ? "CVE-2022-0185 requires exactly CAP_SYS_ADMIN or an unprivileged user " +
              "namespace to reach host-root via fsconfig. The capability this finding " +
              "flags supplies that precondition directly."
            : "CVE-2022-0492 requires CAP_SYS_ADMIN to weaponise cgroup v1 release_agent " +
              "for container escape. Multiple dangerous capabilities and privileged mode " +
              "all satisfy the precondition.",
      })
      .verification(stepInspectCapabilityDeclaration(hit))
      .verification(stepRecordConfigPointer(hit))
      .verification(stepCheckDropAllCompanion(hit))
      .verification(stepCheckSeccompAppArmor(hit));

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

function buildImpactScenario(hit: P2Hit): string {
  if (hit.kind === "namespace") {
    switch (hit.spec.id) {
      case "privileged":
        return (
          `Privileged container can mount host filesystems, load kernel modules, ` +
          `access /dev/*, and enumerate every cgroup — pivoting to host root via ` +
          `CVE-2022-0492 (release_agent) or /proc/self/exe overwrite (CVE-2019-5736) ` +
          `is trivial.`
        );
      case "hostPID":
        return (
          `With host PID namespace, the container can ptrace the kubelet or any ` +
          `sibling container process, reading their memory (secrets, JWTs) or ` +
          `injecting code via ptrace(PTRACE_ATTACH) + POKE.`
        );
      case "hostIPC":
        return (
          `Host IPC sharing exposes SysV shared memory / semaphores across ` +
          `containers — shared-memory credential stores and inter-process caches ` +
          `become readable.`
        );
      case "hostNetwork":
        return (
          `With host network, the container binds host ports (kubelet 10255), ` +
          `reaches 169.254.169.254 metadata, and ARP-spoofs sibling pods.`
        );
      case "hostUsers-false":
        return (
          `Disabling user-namespace remapping means root-in-container is root-on-host. ` +
          `Any container escape primitive now produces host-root directly.`
        );
    }
  }
  switch (hit.spec.kind) {
    case "mount-escape":
      return (
        `CAP_SYS_ADMIN exposes mount/pivot_root/unshare — attacker remounts the ` +
        `host / inside the container, accesses every file on the node, and ` +
        `weaponises CVE-2022-0185 for direct host root.`
      );
    case "kernel-module-load":
      return (
        `Loading an arbitrary kernel module supplies direct kernel code execution ` +
        `— every security boundary becomes advisory.`
      );
    case "cross-container-debug":
      return (
        `ptrace across sibling containers lets the attacker read their memory ` +
        `(tokens, session keys) and inject code into long-lived processes.`
      );
    case "network-manipulation":
      return (
        `NET_ADMIN manipulates iptables / routing — attacker can ARP-spoof ` +
        `sibling pods, intercept TLS-minus-SNI traffic, and redirect metadata ` +
        `lookups.`
      );
    case "packet-capture":
      return (
        `NET_RAW enables promiscuous packet capture on the pod network — ` +
        `credentials and API tokens in transit become readable.`
      );
    case "filesystem-bypass":
      return (
        `DAC_OVERRIDE / DAC_READ_SEARCH bypass POSIX permissions — every file ` +
        `the container can reach becomes readable/writable regardless of mode bits.`
      );
    case "uid-gid-override":
      return (
        `Arbitrary UID/GID transitions bypass the intended identity — combined ` +
        `with a mount or host-share, this produces full host access.`
      );
    case "all-capabilities":
      return (
        `cap_add: ALL is equivalent to privileged: true with respect to Linux ` +
        `capability bitmasks. Every host-primitive attack is available.`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `P2 charter caps confidence at ${cap} — runtime seccomp / AppArmor / ` +
      `user-namespace-remap profiles can partially defeat the escape path.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new DangerousCapabilitiesRule());

export { DangerousCapabilitiesRule };
