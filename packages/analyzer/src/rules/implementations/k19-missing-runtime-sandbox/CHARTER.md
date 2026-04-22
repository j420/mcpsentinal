---
rule_id: K19
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: cve
    id: CVE-2019-5736
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
  - kind: cve
    id: CVE-2022-0185
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-0185
  - kind: cve
    id: CVE-2022-0492
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-0492
  - kind: spec
    id: ISO-27001-A.8.22
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.22 "Segregation of networks"
      requires that networks and systems are segregated based on trust,
      sensitivity, or business function. A container running with
      `privileged: true`, `--cap-add=SYS_ADMIN`, `hostPID: true`, or a
      disabled seccomp profile breaks this segregation at the OS kernel
      level — the container shares trust with the host.
  - kind: spec
    id: CIS-Kubernetes-Baseline
    url: https://www.cisecurity.org/benchmark/kubernetes
    summary: >
      CIS Kubernetes Benchmark §5.2 "Pod Security Standards — Baseline"
      forbids privileged containers (§5.2.1), privilege escalation
      (§5.2.5), host namespace sharing (§5.2.2-4), and running as root
      (§5.2.6). The baseline profile is the *minimum* posture required
      for multi-tenant clusters — anything less leaves the node kernel
      directly reachable from an MCP container.
  - kind: spec
    id: NIST-SP-800-190-Section-4.5
    url: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
    summary: >
      NIST SP 800-190 §4.5 "Orchestrator Risks" enumerates privileged
      containers, host-namespace sharing, and disabled mandatory access
      controls (AppArmor / SELinux / seccomp) as the top orchestrator
      risks. The spec is explicit that ALL three must be enforced — a
      seccomp profile alone does not compensate for a privileged flag.

lethal_edge_cases:
  - >
    Compensating control dead code — the YAML declares a securityContext
    with `runAsNonRoot: true` and `readOnlyRootFilesystem: true`, but
    ALSO declares `privileged: true` on the same container. The
    privileged flag silently neutralises every other security context
    field at runtime. A mitigation-scanning rule that stops at the
    first positive signal reports a false negative — the rule must
    check the authoritative disable flags EVEN WHEN compensating
    controls appear elsewhere.
  - >
    Capability-smuggling via --cap-add=ALL — some manifests split the
    flag across lines (`--cap-add=` on one line, `ALL` on the next)
    or express it as a YAML list (`capabilities: { add: [ALL] }`). A
    regex looking for the literal string `--cap-add=ALL` misses the
    YAML-list variant. The rule must tokenise capability declarations
    structurally and flag any occurrence of ALL or SYS_ADMIN as the
    added capability, regardless of syntax.
  - >
    Host namespace sharing without --privileged — `hostPID: true`,
    `hostNetwork: true`, `hostIPC: true` each break container
    isolation individually. A non-privileged container with
    `hostPID: true` can still read /proc/<pid>/environ on every
    other workload on the node, including the Kubelet. The rule must
    treat each host-namespace flag as an independent sandbox defeat,
    not require the combination with privileged mode.
  - >
    seccomp: Unconfined as a deliberate choice — developers sometimes
    set `seccompProfile: { type: Unconfined }` to debug a syscall
    issue, then forget to revert. The rule must flag `Unconfined`
    exactly — the default-empty seccompProfile is a separate
    compliance question (baseline requires RuntimeDefault) that needs
    a different finding category. Confusing the two creates both
    false positives (on default-empty) and false negatives (on
    explicitly-Unconfined where the user thinks "I didn't set it").
  - >
    Commented-out disable flags survive copy-paste — a line like
    `# privileged: true` in a comment is not a live setting, but
    `privileged: true  # TODO disable for prod` absolutely is. The
    rule must skip lines that start with `#` (YAML comment) or `//`
    (some compose-style tools) after whitespace-trim, but must NOT
    skip lines with an inline trailing comment.

edge_case_strategies:
  - privileged-always-checked
  - capability-tokenised-recognition
  - host-namespace-independent-flags
  - seccomp-unconfined-explicit
  - comment-line-skip

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - sandbox_disable_flag_found
    - compensating_controls_detected
    - flag_category
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Pod Security Admission (PSA) baseline-or-stricter enforcement becomes
    the DEFAULT on Kubernetes and Docker enforces `userns-remap` without
    opt-in — at which point sandbox misconfiguration is rejected at admit
    time and source-level detection becomes belt-and-braces.

mutations_survived: []
mutations_acknowledged_blind: []
---

# K19 — Missing Runtime Sandbox Enforcement

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Dockerfiles, docker-compose YAML, Kubernetes manifests,
and shell scripts that launch MCP server containers.

## What an auditor accepts as evidence

A CIS Kubernetes Benchmark §5.2 / ISO 27001 A.8.22 auditor will not accept
"container is misconfigured" as a finding. They will accept:

1. **Scope proof** — the finding names a specific disable flag, with a
   `source`-kind Location pointing at the exact line. Each disable flag is
   a separate finding; a pod with `privileged: true` AND `hostPID: true`
   produces two findings, because each is a distinct §5.2 control failure.

2. **Gap proof** — the finding identifies the flag's *category*
   (privileged-mode / capability-addition / security-profile-disable /
   host-namespace-share / privilege-escalation). Category-specific
   remediation text follows.

3. **Mitigation check** — the rule inspects the same file for
   compensating controls (runAsNonRoot, readOnlyRootFilesystem,
   cap-drop ALL, seccompProfile: RuntimeDefault). A compensating control
   lowers confidence but does NOT suppress the finding — lethal edge
   case #1 forbids letting a compensating control mask the authoritative
   disable.

4. **Impact statement** — the concrete container-escape scenario tied to
   the real CVE that weaponises this flag: `privileged: true` +
   CVE-2022-0492 (cgroup release_agent), `CAP_SYS_ADMIN` + CVE-2022-0185
   (fsconfig heap overflow), runC → CVE-2019-5736 (host binary overwrite).
   The auditor walks away with "here is how this becomes host-root".

## What the rule does NOT claim

- It does not claim that every privileged container is an active
  exploitation — legitimate uses exist (Docker-in-Docker builders, CNI
  plugins). The finding is "posture gap present" with remediation text.
- It does not verify runtime state — a YAML with `privileged: true` that
  a downstream admission controller mutates to `false` before apply is
  still flagged. That's a false positive category the rule knowingly
  accepts because the source-level policy is the authoritative statement.

## Why confidence is capped at 0.85

The rule sees source-level policy (Dockerfile, compose YAML, k8s manifest).
It does not see admission-controller mutations, Kyverno / OPA Gatekeeper
policies that reject the pod, or runtime rewrites. The 0.85 cap preserves
room for those out-of-file compensating controls that would downgrade the
finding from "active gap" to "posture risk".
