---
rule_id: P7
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: cve
    id: CVE-2019-5736
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
  - kind: spec
    id: Kubernetes-PodSecurity-Restricted
    url: https://kubernetes.io/docs/concepts/security/pod-security-standards/
    summary: >
      Kubernetes Pod Security Standards "Restricted" profile forbids
      hostPath volumes entirely — "volumes must be of type configMap,
      csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim,
      projected, or secret". A pod spec with hostPath, even a narrow
      one, fails the Restricted profile and requires a namespace-level
      exception annotation. This rule is the source-level pre-check
      that catches posture gaps before admission controllers do.
  - kind: spec
    id: CIS-Kubernetes-Benchmark-5.2.3
    url: https://www.cisecurity.org/benchmark/kubernetes
    summary: >
      CIS Kubernetes Benchmark §5.2.3 "Minimize the admission of
      containers wishing to share the host PID or IPC namespace" and
      §5.2.9 "Minimize the admission of containers with allowPrivilegeEscalation"
      combine with the hostPath restriction in the Restricted profile
      to form the standard defense against container-escape-to-host-root
      chains. CVE-2019-5736 is a classic example: a hostPath of / + a
      runC overwrite primitive yields host-root in seconds.

lethal_edge_cases:
  - >
    Partial-root mounts — `hostPath: /var` or `hostPath: /etc` are
    narrow-looking but still grant access to the host's docker socket
    (under /var/run), systemd unit files (under /etc/systemd), kubelet
    credentials (under /etc/kubernetes), SSH host keys (/etc/ssh).
    The rule must flag ANY path under /, /etc, /root, /var, /proc,
    /sys, /dev, /home, and all SSH keys / kubelet credential paths —
    not only the exact full-root case.
  - >
    subPath tricks — `hostPath: /var/run` + `subPath: docker.sock`
    produces an effective mount of /var/run/docker.sock that many
    rules miss. The rule must flag subPath values that extend a host
    path into a sensitive region, not only top-level paths.
  - >
    Dev-loop ~/.kube/config mount — a common developer convenience is
    to bind-mount ~/.kube/config into a CI runner. The mounted config
    contains the cluster admin credentials. The rule must flag ~/.
    patterns and $HOME-relative patterns as well as absolute paths.
  - >
    Read-only is not a mitigation — `hostPath: /` with `readOnly: true`
    still exposes every file on the host to the container for reading
    (SSH host keys, shadow file, TLS certs, kubelet config). Read-only
    is a reduction in posture gap but not an elimination; the rule
    flags read-only mounts with a slight negative adjustment but does
    not suppress the finding.
  - >
    Kubelet credential paths — /var/lib/kubelet and /var/lib/kubernetes
    contain service-account tokens that let any binary impersonate
    the node's kubelet. A pod that mounts these paths (even read-only)
    can enumerate every secret the node can see. The rule's sensitive-
    path vocabulary must include the kubelet credential locations.

edge_case_strategies:
  - partial-root-enumeration
  - subpath-extension-analysis
  - home-relative-path-detection
  - readonly-acknowledged-not-mitigation
  - kubelet-credential-path-coverage

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - host_path_variant
    - mount_context
    - readonly_flag_present
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Every production Kubernetes cluster enforces Pod Security Standards
    Restricted by default AND Docker refuses --volume arguments against
    sensitive host paths. Neither is the default today; until both land
    this rule is the earliest stop-gap.
---

# P7 — Sensitive Host Filesystem Mount

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** docker-compose YAML, Kubernetes manifests, Dockerfile
VOLUME instructions, shell launch scripts using docker run -v /
--mount, Podman / cri-o equivalents.

## What an auditor accepts as evidence

A CIS Kubernetes §5.2.3 / Pod Security Standards Restricted auditor
wants:

1. **Scope proof** — specific YAML / compose / shell line mounting a
   sensitive host path, with a `source`-kind Location. Each mount site
   produces one finding, labelled with the variant (hostPath root,
   /etc, /var/run/docker.sock, ~/.ssh, ~/.kube/config, kubelet
   credentials).

2. **Gap proof** — the mounted path is in the sensitive-path registry.
   The rule labels read-only mounts separately (reduction in posture
   gap, not elimination) and surfaces subPath extensions that produce
   effective sensitive mounts.

3. **Impact statement** — concrete escape scenario tied to CVE-2019-5736
   (runC /proc/self/exe overwrite on a host-mount primitive) or to
   kubelet credential harvesting (read /var/lib/kubelet/pki/*.key and
   impersonate the node).

## What the rule does NOT claim

- It does not claim every hostPath mount is unjustified — node-
  exporters, log collectors, and CNI plugins sometimes legitimately
  need narrow host access. The remediation text requires operator
  justification and explicit exception annotations.
- It does not verify namespace-level PodSecurityPolicy or OPA
  Gatekeeper rules that might reject the pod at admission; the rule
  produces a source-level posture finding independent of admission.

## Why confidence is capped at 0.85

Host paths are unambiguous in source; the uncertainty is whether
namespace-level admission controllers or seccomp / AppArmor profiles
reduce the exploit reach. Read-only mounts further reduce the posture
gap (but do not eliminate it). 0.85 preserves room for those
mitigations without suppressing the finding.
