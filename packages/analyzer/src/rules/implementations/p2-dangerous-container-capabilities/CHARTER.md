---
rule_id: P2
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: cve
    id: CVE-2022-0185
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-0185
  - kind: cve
    id: CVE-2022-0492
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-0492
  - kind: spec
    id: CIS-Docker-Benchmark-5.3-5.22
    url: https://www.cisecurity.org/benchmark/docker
    summary: >
      CIS Docker Benchmark §5.3 (drop all capabilities), §5.4 (no
      privileged mode), and §5.22 (no hostPID / hostIPC / hostNetwork)
      together forbid the capability / namespace posture this rule
      detects. The benchmark is explicit that privileged: true is
      equivalent to "root on host" — every seccomp, AppArmor, and
      cgroup boundary is disabled simultaneously. Capability adds beyond
      the default set (especially SYS_ADMIN, SYS_MODULE, SYS_PTRACE,
      NET_ADMIN, NET_RAW, DAC_OVERRIDE, DAC_READ_SEARCH) each grant a
      specific host-level escape primitive.
  - kind: spec
    id: Kubernetes-PodSecurity-Restricted
    url: https://kubernetes.io/docs/concepts/security/pod-security-standards/
    summary: >
      Kubernetes Pod Security Standards "Restricted" profile (GA in
      v1.25) explicitly bans privileged: true, host namespace sharing
      (hostPID / hostIPC / hostNetwork), and any capability add beyond
      NET_BIND_SERVICE. Workloads failing the Restricted profile require
      namespace-level exception annotations — detection of the unprotected
      posture in MCP-server manifests pre-dates admission-controller
      enforcement and is the earliest place to stop the posture gap.

lethal_edge_cases:
  - >
    Case-variance on capability name — Docker and Kubernetes
    capability-list parsers are case-insensitive in practice
    (sys_admin, SYS_ADMIN, Sys_Admin all resolve to CAP_SYS_ADMIN).
    A rule that only matches uppercase forms false-negatives on the
    common lowercase style. The vocabulary must match case-insensitively
    with OR without the CAP_ prefix.
  - >
    cap_drop=ALL + cap_add=SYS_ADMIN — operators sometimes "drop all"
    and then re-add a single dangerous capability, believing the
    benchmark is satisfied because the default set is restricted. It
    is not: the one add is what matters. The rule must flag the
    dangerous add independent of any drops in the same block.
  - >
    privileged: true WITHOUT an explicit capability list — privileged
    mode implicitly grants ALL capabilities and disables seccomp /
    AppArmor / user namespace mapping. A rule that only scans a
    `capabilities.add:` key misses the implicit form. The rule must
    flag `privileged: true` as an unconditional trigger, regardless of
    any capability-drop block in the same spec.
  - >
    Host namespace sharing (hostPID / hostIPC / hostNetwork / hostUsers:
    false) — these are NOT in the capabilities API but give equivalent
    host-reach primitives: hostPID → ptrace across containers, hostIPC
    → shared-memory leakage, hostNetwork → host port binding +
    169.254.169.254 reach. Each is a separate finding with a separate
    remediation.
  - >
    securityContext inheritance — a pod-level securityContext with
    privileged: true is inherited by every container unless overridden.
    A single finding on the pod spec is sufficient; per-container
    scanning would double-count. The rule emits ONE finding per
    distinct declaration (pod-level OR container-level, not both).

edge_case_strategies:
  - case-insensitive-capability-match
  - drop-all-plus-dangerous-add
  - privileged-mode-implicit-capabilities
  - host-namespace-enumeration
  - pod-vs-container-dedup

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - capability_variant
    - declaration_site
    - drop_all_companion
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Pod Security Admission Restricted profile becomes the DEFAULT on
    new Kubernetes clusters AND Docker's default rootless runtime
    rejects --privileged without explicit cluster-admin opt-in. At
    that point source-level detection remains belt-and-braces for
    legacy YAML still in circulation.

mutations_survived: []
mutations_acknowledged_blind: []
---

# P2 — Dangerous Container Capabilities & Privileged Mode

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** docker-compose YAML, Kubernetes manifests, Dockerfile
HEALTHCHECK / RUN lines that set capabilities, and shell launch scripts
that pass `--cap-add` / `--privileged` to the runtime.

## What an auditor accepts as evidence

A CIS Docker §5.3–5.22 / Kubernetes PSS Restricted auditor wants:

1. **Scope proof** — the specific capability or namespace-share
   declaration, with a `config`-kind Location carrying the json_pointer
   into the securityContext / cap_add / capabilities.add / privileged
   key. One finding per distinct declaration.

2. **Gap proof** — the finding identifies which host-level primitive
   the capability unlocks. SYS_ADMIN → mount namespace escape;
   SYS_MODULE → kernel module load; SYS_PTRACE → cross-container
   debugger; NET_ADMIN → iptables / ARP manipulation; DAC_OVERRIDE
   or DAC_READ_SEARCH → bypass POSIX permissions on the host FS.

3. **Impact statement** — concrete container-escape scenario tied to
   CVE-2022-0185 (fsconfig + SYS_ADMIN) and CVE-2022-0492 (cgroup v1
   release_agent + SYS_ADMIN) — both require exactly the capabilities
   the rule flags.

## What the rule does NOT claim

- It does not claim that every dangerous capability is unjustified —
  CNI plugins need NET_ADMIN, some profilers need SYS_PTRACE. The
  finding is "posture requires justification", not "immediate exploit".
- It does not verify seccomp / AppArmor profile contents — a profile
  may further restrict the capability, but the analyzer cannot observe
  that from YAML.

## Why confidence is capped at 0.85

Capabilities are unambiguous in source; the uncertainty is whether
runtime seccomp / AppArmor / user-namespace-mapping profiles defeat
exploitation. 0.85 preserves that room while still producing a
load-bearing "critical posture gap" finding.
