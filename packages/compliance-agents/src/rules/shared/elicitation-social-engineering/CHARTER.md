# Rule Charter: elicitation-social-engineering

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP04, OWASP ASI03, CoSAI T1, CoSAI T5, MAESTRO L6, EU AI Act Art.13, MITRE AML.T0055

## Threat model

The MCP spec 2025-06-18 introduced the **elicitation capability**:
a server can request structured data from the user via the client. It
was designed for legitimate UX flows (asking for a file path, a time
zone, a preferred format) but it is *also* a direct social-engineering
channel: the server renders a prompt, the client forwards it to the
user, and the response returns to the server.

The attacker turns the elicitation channel into a credential-harvesting
or PII-exfiltration surface: the server asks the user to type their
API key, password, one-time code, or personal data "to continue", and
the client dutifully renders the request.

The structural signature: the server declares sampling/elicitation
capability (or uses elicitation via tools) AND has parameters that
accept `credential`, `text_content`, or `identifier` semantics from
the user, without any human-in-the-loop annotation and without cost or
rate-limiting guards.

## Real-world references

- **CVE-2025-ELICIT** — "MCP elicitation credential harvest";
  documented case of a compromised MCP server using elicitation to
  collect OAuth tokens under a plausible UX pretext.
- **OWASP-ASI03** — Identity & Privilege Abuse.
- **NIST-SP-800-63B** — Identity proofing guidance (which the attack
  deliberately short-circuits).

## Lethal edge cases

1. **Elicitation + credential param** — tool requests the user to
   enter an API key directly into an elicitation prompt.
2. **Elicitation + redirect URL** — tool asks the user to visit a
   URL for "authentication" that returns to an attacker-controlled
   endpoint.
3. **Elicitation with no human gate** — the server phrases the request
   in a way the user cannot easily dismiss, using authoritative
   language to bypass skepticism.

## Evidence the rule must gather

- Capability-graph classification: input channels with semantic
  `credential` or `identifier`.
- Tool annotation scan: any consent marker keys present?
- Cross-check: does the server declare sampling or does any tool
  explicitly invoke the elicitation flow based on capability graph
  hints?

## Strategies (for runtime test generation)

- `credential-laundering`
- `consent-bypass`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if
`facts.elicitation_credential_paths` is non-empty AND the LLM's
`evidence_path_used` references one of those tool names.

## Remediation

Never use the elicitation capability for credential collection. Route
all credential flows through a centralized secrets manager. Add
`requiresConfirmation: true` and a warning surface to any tool that
legitimately needs user input. Prefer OAuth 2.1 device flows over
raw credential prompts.

## Traceability (machine-checked)

rule_id: shared-elicitation-social-engineering
threat_refs:
- CVE-2025-ELICIT
- OWASP-ASI03
- NIST-SP-800-63B
strategies:
- credential-laundering
- consent-bypass
- trust-inversion
