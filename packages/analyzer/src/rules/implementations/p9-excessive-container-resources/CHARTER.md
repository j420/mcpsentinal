---
rule_id: P9
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: T1499.001
risk_domain: denial-of-service

threat_refs:
  - kind: cve
    id: CVE-2022-0492
    url: https://nvd.nist.gov/vuln/detail/CVE-2022-0492
  - kind: cve
    id: CVE-2017-16995
    url: https://nvd.nist.gov/vuln/detail/CVE-2017-16995
  - kind: spec
    id: CIS-Docker-Benchmark-5.10-5.14
    url: https://www.cisecurity.org/benchmark/docker
    summary: >
      CIS Docker Benchmark §5.10 memory limits, §5.11 CPU limits, §5.12
      PID limits, §5.13 ulimits, §5.14 open-file limits — each is a
      separate control; the benchmark is explicit that setting only
      some limits is not compensating. A container with memory limits
      but no PID limit can still fork-bomb the host.
  - kind: spec
    id: NIST-SP-800-190-Section-5.6
    url: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
    summary: >
      NIST SP 800-190 §5.6 "Runtime Risks" enumerates resource exhaustion
      as a primary runtime risk; recommends namespace-level LimitRange +
      container-level resource limits as the defense-in-depth posture.
      The spec is clear that CGroups alone without per-container limits
      are insufficient — pid cgroups default to unbounded on most kernels.
  - kind: spec
    id: Kubernetes-LimitRange
    url: https://kubernetes.io/docs/concepts/policy/limit-range/
    summary: >
      Kubernetes LimitRange and ResourceQuota are the admission-time
      enforcement layer. A pod spec without `resources.limits.{cpu,memory}`
      is rejected by LimitRange-enforced namespaces. MCP server deployments
      that omit limits are either running in an unprotected namespace or
      rely on kubelet defaults — both failure modes are DoS-amplifiers.

lethal_edge_cases:
  - >
    Requests without limits — a pod spec has `resources.requests.memory:
    512Mi` but no `resources.limits.memory`. This is a *different* failure
    mode from no resource block at all: the scheduler places the pod, but
    the container can consume unbounded memory once running. The rule must
    distinguish "no resources block" from "requests but no limits" — they
    need different remediation text.
  - >
    PID limits absent even when memory/CPU are set — CIS §5.12 is an
    independent control. A container with `memory: 1Gi, cpu: 1000m` but
    no `pids_limit` / `pids.max` can launch a fork bomb that exhausts
    every PID slot on the host (default 32768), bringing down the kubelet
    and every co-located container. The rule must flag missing PID limits
    independently of memory/CPU presence.
  - >
    Inverted numeric limits — `memory: -1` / `cpu: 0` / `--pids-limit=-1`
    all mean "unlimited" to Docker and Kubernetes respectively. The rule
    must recognise these sentinel values in addition to the literal
    "unlimited" / missing keys. A sentinel-miss here is "we set a limit"
    (with a weak config review) when in fact no limit is applied.
  - >
    String-suffixed excessive values — `memory: "1024Gi"` is 1 TB of
    memory on a 128 GB node; the container will OOM-kill constantly but
    the ADMISSION check passes because the key is present. The rule must
    flag numeric values that exceed a reasonable threshold (>32 Gi for
    memory, >16 CPUs) as "excessive", not just "missing".
  - >
    Compose `deploy.resources.limits` vs `resources.limits` — docker-
    compose has two different paths (top-level `resources:` vs under
    `deploy: resources: limits:`) and the semantics differ between
    `docker compose up` (ignores deploy) and `docker stack deploy` (uses
    deploy). The rule must check BOTH paths — a config that only sets
    `deploy.resources.limits` is protected in Swarm but not in Compose,
    a significant posture split the rule highlights explicitly.

edge_case_strategies:
  - requests-vs-limits-distinction
  - pid-limit-independent-check
  - sentinel-unlimited-recognition
  - excessive-numeric-detection
  - compose-vs-deploy-path-check

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - missing_or_excessive_limit
    - resource_kind
    - compensating_requests_present
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Kubernetes ships with a default LimitRange that rejects admission for
    any pod without `resources.limits.{cpu,memory,pids}` AND Docker's
    default runtime enforces per-container pid/cpu/memory caps without
    opt-in — at which point the findings become historical posture.

mutations_survived: []
mutations_acknowledged_blind: []
---

# P9 — Missing Container Resource Limits

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Dockerfiles, docker-compose YAML, Kubernetes manifests, and
shell scripts that launch MCP server containers.

## What an auditor accepts as evidence

A CIS Docker §5.10-5.14 / NIST SP 800-190 §5.6 auditor wants:

1. **Scope proof** — the finding names the specific missing-or-excessive
   resource (memory / cpu / pids / ulimit), with a `config`-kind Location
   pointing at the absence or the excessive value. Missing values
   surface via the negative-space json_pointer (`/resources/limits/memory`
   when the key is absent); excessive values point to the actual key.

2. **Gap proof** — the finding identifies which DoS primitive the missing
   limit enables. Missing memory → OOM kill of co-located containers.
   Missing CPU → noisy-neighbor starvation. Missing PIDs → fork-bomb.
   Missing ulimit nofile → fd-exhaustion DoS.

3. **Mitigation check** — the rule reports whether `requests` are present
   without `limits` (lethal edge case #1 — partial config). A pod with
   memory requests but no memory limit is at higher risk than one with
   neither, because the scheduler places the pod in a false sense of
   safety.

4. **Impact statement** — concrete DoS scenario tied to CVE-2017-16995
   (fork-bomb amplifier) and CVE-2022-0492 (cgroup escape weaponised by
   PID exhaustion).

## What the rule does NOT claim

- It does not claim that every production namespace is missing a
  LimitRange — namespace-level enforcement may supply the default.
  The finding is "pod spec is not self-protecting," which stands
  regardless of namespace policy.
- It does not verify runtime enforcement — a pod spec with
  `pids_limit: 10000` might be rewritten to 32768 by a mutating
  webhook; the analyzer cannot observe that.

## Why confidence is capped at 0.75

The rule sees source-level policy only. Namespace-level LimitRange /
ResourceQuota, defaulting admission webhooks, and Docker daemon-level
`default-ulimits` can all supply compensating defaults the analyzer
cannot observe. The 0.75 cap is lower than K19's 0.85 because the
out-of-file mitigations are more common in practice — most enterprise
clusters DO apply namespace LimitRange.
