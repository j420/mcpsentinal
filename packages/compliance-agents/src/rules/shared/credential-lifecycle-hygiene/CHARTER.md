# Rule Charter: credential-lifecycle-hygiene

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP07, OWASP ASI03, CoSAI T1, MAESTRO L6, EU AI Act Art.15, MITRE AML.T0055

## Threat model

A server exposes tools that handle credentials — tokens, API keys,
passwords, session cookies — but does not bind a secrets-management
library and does not declare the credential lifecycle (issuance,
rotation, revocation). The attacker who compromises one session can
replay credentials indefinitely because nothing rotates them and
nothing revokes a leaked token.

This is the "long-lived credential" failure mode behind multiple real
incidents: leaked GitHub PATs in npm post-install hooks, AWS session
keys embedded in MCP config, OAuth refresh tokens logged to disk.

## Real-world references

- **CVE-2024-37032** — Ollama long-lived key exposure.
- **GHSA-CREDS-2025** — long-lived GitHub token leaked via MCP config.
- **OWASP-ASI03** — Identity & Privilege Abuse, top-3 agentic risk.
- **NIST-SP-800-63B** — credential lifecycle requirements.

## Lethal edge cases

1. **Environment-variable credentials with no rotation hook** — tools
   accept an `api_key` argument that the server reads from `process.env`
   with no expiry.
2. **Hardcoded refresh tokens** — refresh tokens in source with no
   revocation endpoint.
3. **Shared credentials across agents** — one token used for both a
   reader and a writer, violating least-privilege.
4. **OAuth client credentials without scope narrowing** —
   `openid email offline_access` at `full_access` when `read:me` suffices.

## Evidence the rule must gather

- Capability-graph classification: which tools declare
  `manages-credentials`.
- Source-file token scan: is ANY centralized secrets-manager binding
  present (vault, AWS SecretsManager, Azure KeyVault, Doppler, Keytar)?
- Tool annotations: do any tools carry a rotation/expiry marker?
- Input parameter semantic scan: which parameters are typed `credential`?

## Strategies (for runtime test generation)

- `credential-laundering`
- `privilege-chain`
- `auth-bypass-window`

## Judge contract

A "fail" verdict is confirmed only if the bundle's
`facts.credential_handlers_without_vault` is non-empty AND the LLM's
`evidence_path_used` references one of those tool names.

## Remediation

Bind a secrets-management library, source credentials from it on every
tool invocation, declare an explicit rotation schedule, and annotate
credential-handling tools with the rotation window. Never accept raw
long-lived credentials as tool parameters.

## Traceability (machine-checked)

rule_id: shared-credential-lifecycle-hygiene
threat_refs:
- CVE-2024-37032
- GHSA-CREDS-2025
- OWASP-ASI03
- NIST-SP-800-63B
strategies:
- credential-laundering
- privilege-chain
- auth-bypass-window
