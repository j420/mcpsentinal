---
rule_id: P10
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: T1557
risk_domain: container-runtime

threat_refs:
  - kind: cve
    id: CVE-2019-5736
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
  - kind: spec
    id: CIS-Docker-Benchmark-5.9
    url: https://www.cisecurity.org/benchmark/docker
    summary: >
      CIS Docker Benchmark §5.9 "Ensure that the host's network
      namespace is not shared" explicitly forbids --network=host for
      production containers. The rationale is that host networking
      bypasses every Docker network isolation control — the container
      shares the node's routing table, arp cache, and binds directly
      to host ports without the userland proxy.
  - kind: spec
    id: CIS-Kubernetes-Benchmark-5.2.4
    url: https://www.cisecurity.org/benchmark/kubernetes
    summary: >
      CIS Kubernetes Benchmark §5.2.4 disallows pods with
      hostNetwork: true in multi-tenant clusters. The control covers
      both inbound traffic (ability to bind host ports that bypass
      NetworkPolicy) and outbound (ability to reach localhost-only
      services like the kubelet's 10250/10255 debug endpoints and the
      metadata service at 169.254.169.254).
  - kind: paper
    id: Unit42-Container-Escape-Host-Net
    url: https://unit42.paloaltonetworks.com/container-escape-techniques/
    summary: >
      Palo Alto Unit 42 container-escape research (2023–2025) documents
      multiple in-the-wild incidents where a compromised workload
      escalated from "code execution in container" to "read every
      cluster secret" by: (a) binding to host port 10255 and pivoting
      to the kubelet read-only API, (b) ARP-spoofing the node's mDNS
      to impersonate internal services, (c) reading the cloud
      metadata service to steal the node IAM credentials.

lethal_edge_cases:
  - >
    CLI variants — `--net=host` and `--network=host` are both valid
    Docker CLI syntax for the same host-network escape. The rule must
    recognise BOTH forms (the shorter one is an alias that persists
    for backward compatibility). Missing one form is a false negative.
  - >
    Compose `network_mode: "host"` vs Kubernetes `hostNetwork: true` —
    different keys express the same posture. A rule with only one
    branch misses the other. The rule must check every expression
    form listed in the data registry and emit one finding per
    matched form (single container can only be in host mode via one
    path, but different services in the same compose file can each
    trigger).
  - >
    Legitimate host-network workloads — CNI plugins (Calico, Flannel),
    node exporters (Prometheus node-exporter), and ingress controllers
    sometimes legitimately need hostNetwork: true. The rule flags
    unconditionally (posture gap) but the remediation text MUST
    acknowledge the legitimate exception class and redirect the
    operator to NetworkPolicy + egress controls rather than simply
    "remove hostNetwork" — otherwise the rule produces friction
    without improving security.
  - >
    Port-binding smuggling — a container without hostNetwork: true but
    with `ports: [{ hostNetwork: true }]` in the hostNetwork: true
    position of a podSpec is still sharing the host namespace. The
    rule must not interpret `hostNetwork` as a ports property — it
    is always a top-level podSpec key in Kubernetes, a service-level
    key in Compose. A nested match is likely a false positive.
  - >
    Case-variant keys — Docker CLI is case-sensitive (`--network=Host`
    is an error) but YAML parsers are often case-insensitive for
    boolean values (`true` vs `True` vs `TRUE`). The rule must match
    the boolean value case-insensitively but the KEY case-sensitively
    for Kubernetes (`hostNetwork` is camelCase per the API schema) and
    flag case-altered keys as suspicious (probable typo that would
    fail admission anyway).

edge_case_strategies:
  - cli-form-enumeration
  - k8s-compose-dual-branch
  - legitimate-exception-redirect
  - top-level-only-matching
  - case-sensitive-key-matching

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - host_network_mode_detected
    - network_isolation_alternatives_detected
    - variant_form
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Pod Security Admission Restricted profile becomes the default on
    new Kubernetes clusters AND Docker refuses --network=host without
    explicit capability opt-in — at which point source-level detection
    is belt-and-braces for pods that no longer ship.
---

# P10 — Host Network Mode and Missing Egress Controls

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Dockerfiles, docker-compose YAML, Kubernetes manifests,
shell launch scripts.

## What an auditor accepts as evidence

A CIS Docker §5.9 / CIS Kubernetes §5.2.4 / Unit 42 container-escape
auditor wants:

1. **Scope proof** — specific line + specific variant form. A finding on
   `network_mode: host` (compose) is materially different from one on
   `hostNetwork: true` (k8s) and the auditor tracks them separately.

2. **Gap proof** — the exact network-isolation control being defeated:
   inbound binding past the userland proxy, outbound reach to localhost-
   only services (kubelet 10250/10255, metadata 169.254.169.254), and
   ARP / mDNS spoofing on the shared link layer.

3. **Mitigation check** — the rule reports whether any network-isolation
   alternative (bridge/overlay/internal network, NetworkPolicy) is
   present in the same file. An hostNetwork: true paired with a strict
   NetworkPolicy is materially safer than hostNetwork alone.

4. **Impact statement** — the specific cluster-escape scenario tied to
   Unit 42 / CVE-2019-5736 class incidents.

## What the rule does NOT claim

- It does not claim that every host-network workload is compromised —
  CNI plugins, node-exporters, and ingress controllers sometimes require
  it. The finding is "posture gap requires justification".
- It does not verify NetworkPolicy correctness — a policy object might
  exist but allow everything. Admission-controller validation is
  out-of-scope here.

## Why confidence is capped at 0.80

Host network is unambiguous in source; the uncertainty is whether the
operator has applied compensating NetworkPolicy + egress controls the
analyzer cannot observe. 0.80 preserves that room.
