# Rule Charter: supply-chain-integrity-attestation

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP10, OWASP ASI04, CoSAI T6, CoSAI T11, MAESTRO L4, EU AI Act Art.15, MITRE AML.T0056

## Threat model

An MCP server is installed from a package registry or git source with **no
cryptographic integrity attestation**: no lockfile with hashes, no SLSA
provenance, no sigstore/cosign signature, no in-toto statements, no
checksum manifest. An attacker who compromises the registry mirror,
CI pipeline, or developer account can substitute a malicious version of
the server or any of its transitive dependencies, and nothing in the
install path verifies authenticity.

This is the class of attack behind event-stream (2018), ua-parser-js
(2021), Ledger Connect Kit (2023), xz-utils (CVE-2024-3094), and the
2024 PyPI "colorama" typosquat campaign. For MCP specifically, the
attacker gets code execution in the AI runtime with no user interaction,
because MCP servers run as trusted local processes.

The rule does NOT require a specific tool (Sigstore vs. cosign vs. SLSA).
It requires SOMETHING in the install path to attest that the bytes we
loaded are the bytes the author intended. An absence of any attestation
marker is a structural failure that compliance frameworks explicitly
call out (EU AI Act Art.15 "cybersecurity", CoSAI T6 "supply chain").

## Real-world references

- **CVE-2024-3094** — xz-utils backdoor shipped through maintainer
  compromise; no reproducible build or provenance caught it for months.
- **GHSA-EVENT-STREAM-2018** — event-stream malicious update; pure trust
  in npm author with no signature verification.
- **OWASP-MCP10** — Supply Chain is the top-10 MCP risk.
- **SLSA-V1.0** — Supply-chain Levels for Software Artifacts framework
  the rule aligns against.
- **NIST-SP-800-204D** — Software supply chain security for cloud-native
  applications.

## Lethal edge cases

1. **Unpinned dependency range** — `"^1.0.0"` in package.json and no
   lockfile committed, so every install resolves fresh and a malicious
   1.0.1 lands immediately.
2. **Git dependency without commit pin** — `git+https://.../repo.git`
   with no `#<sha>`, so a force-push rewrites the installed code.
3. **Transitive CVE with no advisory gate** — the top-level is pinned
   but a transitive pulls in a package with a known CVE the analyzer
   already flagged; the absence of a remediation path is the violation.
4. **No lockfile AND no attestation AND CVE-tagged deps** — the full
   trifecta: the server lives downstream of trust infrastructure it
   does not use at all.

## Evidence the rule must gather

- Source-file token scan: is ANY integrity attestation marker present
  (sigstore / cosign / in-toto / SLSA / package-lock / pnpm-lock /
  poetry.lock / cargo.lock / requirements.txt.sha256)?
- Dependency list inspection: how many deps have `has_known_cve = true`?
- Dependency list inspection: how many deps are unpinned / have a
  version string that looks like a range rather than a concrete tag?
- Cross-fact: the combination of "no attestation marker" AND "≥1
  CVE-tagged dependency" is the deterministic violation.

## Strategies (for runtime test generation)

- `supply-chain-pivot`
- `config-drift`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if the bundle's
`facts.attestation_markers_found` array is empty AND
`facts.cve_tagged_deps` is non-empty AND the LLM's
`evidence_path_used` references one of the CVE-tagged dep names or the
string `integrity_attestation`.

## Remediation

Commit a lockfile (`package-lock.json`, `pnpm-lock.yaml`, `poetry.lock`,
`Cargo.lock`) with integrity hashes. Adopt SLSA-Level-2 provenance or
Sigstore cosign signing for releases. Gate installs on an advisory
scanner (osv-scanner, npm audit, pip-audit) and fail closed on HIGH or
CRITICAL advisories. For git dependencies, pin the exact commit SHA.

## Traceability (machine-checked)

rule_id: shared-supply-chain-integrity-attestation
threat_refs:
- CVE-2024-3094
- GHSA-EVENT-STREAM-2018
- OWASP-MCP10
- SLSA-V1.0
- NIST-SP-800-204D
strategies:
- supply-chain-pivot
- config-drift
- trust-inversion
