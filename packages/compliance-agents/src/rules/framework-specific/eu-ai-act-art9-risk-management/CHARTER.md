# Rule Charter: eu-ai-act-art9-risk-management

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** EU AI Act Art.9 — Risk Management System

## Threat model

EU AI Act Article 9 requires high-risk AI providers to "establish,
implement, document and maintain a risk management system". For an
MCP server supplying tools into an agentic pipeline, that system has
two structurally-checkable artifacts:

1. **Supply-chain integrity attestation**: locked manifests, signed
   releases, or SLSA/in-toto provenance data in the source tree —
   evidence that third-party risk is tracked.
2. **Declared capabilities surface**: the initialize response MUST
   declare at least one capability (tools/resources/prompts), because
   the risk management system is predicated on knowing what the
   system does. An MCP server that boots with no declared capability
   is by construction un-assessable.

If neither artifact is present, the rule fires a deterministic Art.9
violation.

## Real-world references

- **EU-AI-Act-Art9-1** — risk management mandate for high-risk AI.
- **EU-AI-Act-Art9-2** — iterative process spanning the full lifecycle.
- **NIST-AI-RMF-GOVERN-1** — parallel governance requirement.
- **SLSA-V1.0** — provenance framework accepted as Art.9-compatible
  evidence.

## Lethal edge cases

1. **No lockfile, no SBOM, no SLSA, no declared capability** — total
   absence of risk artifacts.
2. **Lockfile present, capabilities undeclared** — partial coverage;
   the rule still fires because Art.9 requires both.
3. **Declared capabilities but no integrity evidence** — fires.

## Evidence the rule must gather

- `sourceTokenHits` against rule-kit `INTEGRITY_MARKERS`.
- `context.declared_capabilities` presence check.
- Combined deterministic_violation when both are missing.

## Strategies (for runtime test generation)

- `supply-chain-pivot`
- `config-drift`
- `audit-erasure`

## Judge contract

A "fail" verdict is confirmed only if `facts.art9_failures` is
non-empty AND the LLM's `evidence_path_used` references one of the
listed failure ids or the literal `art9_risk_mgmt`.

## Remediation

Check in a lockfile (package-lock.json, pnpm-lock.yaml, poetry.lock),
generate a SLSA v1.0 provenance statement for every release, declare
the `logging` capability in the initialize response, and publish a
signed SBOM attestation.

## Traceability (machine-checked)

rule_id: eu-ai-act-art9-risk-management
threat_refs:
- EU-AI-Act-Art9-1
- EU-AI-Act-Art9-2
- NIST-AI-RMF-GOVERN-1
- SLSA-V1.0
strategies:
- supply-chain-pivot
- config-drift
- audit-erasure
