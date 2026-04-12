# Rule Charter: maestro-l4-deployment-integrity

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** MAESTRO L4 — Deployment & Infrastructure

## Threat model

MAESTRO layer L4 (Deployment & Infrastructure) requires a deployed AI
system to carry provable integrity artifacts end-to-end — source to
runtime. For an MCP server, that decomposes into two structurally
checkable conditions:

1. **Source-tree integrity markers**: at least one of lockfile,
   SLSA provenance, sigstore/cosign, in-toto attestation, or
   hash-pinned manifest. Anchored in rule-kit `INTEGRITY_MARKERS`.
2. **Runtime sandbox markers**: at least one sandbox marker from
   rule-kit `SANDBOX_MARKERS` present in source files (Dockerfiles,
   k8s manifests, systemd units).

Both must hold. A server passing one and failing the other still
fails L4 because L4 is the *union* of supply-chain integrity and
runtime hardening.

## Real-world references

- **MAESTRO-L4-Spec** — MAESTRO threat model layer 4 definition.
- **SLSA-V1.0** — supply-chain integrity framework.
- **CIS-Docker-Benchmark** — runtime hardening baseline.

## Lethal edge cases

1. **Lockfile present, no sandbox** — supply chain OK but runtime
   unconstrained.
2. **Sandbox present, no lockfile** — runtime hardened but upstream
   compromise propagates.
3. **Neither present** — both axes failed.

## Evidence the rule must gather

- `sourceTokenHits` against `INTEGRITY_MARKERS`.
- `sourceTokenHits` against `SANDBOX_MARKERS`.

## Strategies (for runtime test generation)

- `supply-chain-pivot`
- `boundary-leak`
- `config-drift`

## Judge contract

A "fail" verdict is confirmed only if `facts.l4_failures` is non-empty
AND the LLM's `evidence_path_used` references one of the listed
failure ids or the literal `l4_deployment_integrity`.

## Remediation

Check in a lockfile, publish SLSA v1.0 provenance, sign release
artifacts with cosign, AND add a seccomp profile, AppArmor, or
gvisor to the runtime. Both axes are mandatory for L4.

## Traceability (machine-checked)

rule_id: maestro-l4-deployment-integrity
threat_refs:
- MAESTRO-L4-Spec
- SLSA-V1.0
- CIS-Docker-Benchmark
strategies:
- supply-chain-pivot
- boundary-leak
- config-drift
