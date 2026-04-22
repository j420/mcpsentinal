---
rule_id: P1
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
    id: CIS-Docker-Benchmark-5.31
    url: https://www.cisecurity.org/benchmark/docker
    summary: >
      CIS Docker Benchmark §5.31 "Ensure the Docker socket is not mounted
      inside any containers" is a HIGH-priority control. Mounting
      /var/run/docker.sock (or the containerd / cri-o / podman equivalents)
      into a workload container hands that container complete control of
      the daemon: it can create new privileged containers, bind-mount the
      host filesystem into them, and pivot to host root in seconds.
  - kind: paper
    id: Docker-Security-Documentation
    url: https://docs.docker.com/engine/security/#docker-daemon-attack-surface
    summary: >
      Docker's own documentation warns explicitly against mounting the
      daemon socket into containers — the entire daemon-attack-surface
      section exists because this is the #1 container-escape vector
      observed in the wild. MCP servers that mount docker.sock for
      "container orchestration" features are handing the same attack
      surface to any prompt-injected tool invocation.

lethal_edge_cases:
  - >
    Named-volume alias form — `volumes: - docker-sock:/var/run/docker.sock`
    where `docker-sock` is a named volume whose definition elsewhere in
    the file binds the host socket. A naive pattern that only looks at
    the `source:` path misses this. The rule must treat ANY reference
    to a docker / containerd / crio / podman socket path in a volume
    context as suspect, not only `host:container` short-form mounts.
  - >
    Socket-proxy indirection — the popular `tecnativa/docker-socket-proxy`
    image (and the `ghcr.io/linuxserver/docker-socket-proxy` variant)
    mount the socket into the proxy, then expose specific API verbs
    over TCP. The proxy still holds the socket. From a security-review
    perspective, a container mounting the proxy's TCP endpoint is a
    softer version of mounting the socket directly, but a container
    mounting the socket INTO the proxy still satisfies this rule. The
    rule flags the raw mount — proxy-deployment posture is a separate
    review item the remediation text calls out.
  - >
    Kubernetes hostPath + subPath — `hostPath: { path: /var/run }` +
    `volumeMounts: [{ subPath: docker.sock, mountPath: /var/run/docker.sock }]`
    splits the socket reference across two YAML keys. A line-scanner
    that only looks at value fields will miss the reconstruction. The
    rule must flag EITHER a top-level hostPath pointing at a socket
    path OR a volumeMount whose subPath / mountPath tokens concatenate
    to a known socket name.
  - >
    containerd / cri-o / podman equivalents — `/run/containerd/containerd.sock`,
    `/var/run/crio/crio.sock`, `/run/podman/podman.sock` grant the same
    escape primitive on hosts using alternative runtimes. Missing these
    is a critical false-negative. The data table must be exhaustive.
  - >
    Read-only mount myth — `- /var/run/docker.sock:/var/run/docker.sock:ro`
    is NOT a mitigation: the Docker API accepts create/exec over HTTP GET
    query strings in older daemon versions and even on current daemons the
    read-only flag only blocks writes to the socket inode, not API calls
    over it. The rule must flag read-only mounts identically to writable
    ones and emit a remediation note distinguishing the two.

edge_case_strategies:
  - named-volume-alias-scan
  - subpath-reconstruction
  - alternative-runtime-enumeration
  - readonly-not-mitigation
  - socket-proxy-acknowledgement

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - socket_path_variant
    - mount_context
    - readonly_flag_present
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Rootless Docker becomes the deployment default AND MCP-server images
    stop shipping docker-compose examples that bind the socket — at
    which point the finding transitions from "critical active gap" to
    "legacy posture check".

mutations_survived: []
mutations_acknowledged_blind: []
---

# P1 — Docker Socket Mount in Container

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** Dockerfiles, docker-compose YAML, Kubernetes manifests,
shell launch scripts that bind a container-runtime socket into a
workload container.

## What an auditor accepts as evidence

A CIS Docker §5.31 / NIST SP 800-190 auditor wants:

1. **Scope proof** — the specific YAML / Dockerfile / shell line that
   establishes the mount. Both sides of the colon (host path + container
   path) matter; the finding records both via a `config`-kind Location
   with a json_pointer into the volumes block.

2. **Gap proof** — the finding identifies which socket variant is mounted
   (docker vs containerd vs crio vs podman) and whether the mount is
   read-only (same class of finding — read-only does not defeat the
   create-container API).

3. **Impact statement** — concrete container-escape scenario: prompt
   injection → docker API → `docker run --privileged -v /:/host busybox`
   → chroot to host root in under three shell lines.

## What the rule does NOT claim

- It does not claim the mount is unjustified — CI runners, node-exporters,
  and service-mesh sidecars sometimes legitimately need the socket. The
  remediation text explicitly offers Kaniko, rootless Docker, and the
  docker-socket-proxy alternative for each class.
- It does not verify runtime AppArmor / SELinux profiles — a container
  with an AppArmor profile denying the Docker API is materially safer,
  but the analyzer cannot observe that from source.

## Why confidence is capped at 0.85

Socket mounts are unambiguous in source; the uncertainty is whether
daemon-side AppArmor / SELinux / socket-activation policies defeat the
exploitation path. 0.85 preserves room for those out-of-file mitigations
while still producing a load-bearing "critical posture gap" finding.
