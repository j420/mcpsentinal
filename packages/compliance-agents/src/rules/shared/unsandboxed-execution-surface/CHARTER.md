# Rule Charter: unsandboxed-execution-surface

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP07, CoSAI T8, MAESTRO L4, EU AI Act Art.15, ISO 27001 A.8.22

## Threat model

A server that exposes `executes-code` capability tools and runs outside
a structural sandbox (seccomp, apparmor, gvisor, readOnlyRootFilesystem,
runAsNonRoot, firejail, nsjail, bubblewrap) hands every prompt-injection
author a host-level RCE. The existing analyzer rule K19 covers part of
this ground; this compliance rule lifts it into per-framework reports
with richer evidence.

The deterministic anchor is the coincidence of three structural facts:
1. At least one capability-graph node with `executes-code`.
2. Zero hits against rule-kit `SANDBOX_MARKERS` across source files
   (Dockerfiles, k8s manifests, systemd unit files, code literals).
3. No capability of type `accesses-filesystem` carrying a root
   restriction — because if root restriction is absent, filesystem
   reach is unbounded.

If the first two hold, the rule fires deterministically. Framing the
rule this way means the LLM cannot hallucinate a violation: the judge
re-validates the deterministic facts before accepting any verdict.

## Real-world references

- **K19-MCP-Sentinel** — analyzer rule for missing runtime sandbox
  enforcement.
- **CVE-2025-53109** / **CVE-2025-53110** — Anthropic filesystem server
  root-boundary bypass; the underlying failure mode is unsandboxed
  filesystem access.
- **OWASP-MCP07** — Insecure Configuration.
- **CoSAI-T8** — Exploitation of compromised runtime.
- **ISO-27001-A822** — Secure Development; sandbox enforcement is a
  required control for code-executing systems.

## Lethal edge cases

1. **`executes-code` + Dockerfile with no USER directive + no seccomp**
   — root inside container, no syscall filter.
2. **`executes-code` + k8s manifest `runAsUser: 0`** — no privilege drop.
3. **`executes-code` + filesystem tool anchored at `/`** — root-level
   filesystem reach with code execution.

## Evidence the rule must gather

- Capability graph: nodes with `executes-code`.
- Source-file token scan for `SANDBOX_MARKERS`.
- Capability graph: nodes with `accesses-filesystem` — used to
  amplify severity, not to fire the rule alone.

## Strategies (for runtime test generation)

- `privilege-chain`
- `boundary-leak`
- `config-drift`

## Judge contract

A "fail" verdict is confirmed only if `facts.execution_nodes` is
non-empty AND `facts.sandbox_markers_found` is empty AND the LLM's
`evidence_path_used` references one of the execution node tool names
or the literal `unsandboxed_surface`.

## Remediation

Add a structural sandbox: seccomp profile, AppArmor, gvisor/runsc,
`readOnlyRootFilesystem: true`, `runAsNonRoot: true`, `runAsUser: 1000`,
and drop all capabilities. Anchor the filesystem capability at a
dedicated data directory — never `/`.

## Traceability (machine-checked)

rule_id: shared-unsandboxed-execution-surface
threat_refs:
- K19-MCP-Sentinel
- CVE-2025-53109
- CVE-2025-53110
- OWASP-MCP07
- CoSAI-T8
strategies:
- privilege-chain
- boundary-leak
- config-drift
