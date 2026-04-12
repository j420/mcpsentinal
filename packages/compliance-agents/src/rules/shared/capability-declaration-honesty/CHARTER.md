# Rule Charter: capability-declaration-honesty

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP07, OWASP ASI02, CoSAI T7, MAESTRO L4, EU AI Act Art.13

## Threat model

The MCP `initialize` handshake carries a `capabilities` object in which
the server declares the categories of functionality it offers: tools,
resources, prompts, sampling, logging. Clients use this declaration to
decide which request types are allowed; a server that **uses** a
capability it did not declare is performing undeclared privilege
escalation.

The inverse is also a violation, though less severe: a server that
declares a capability it does not actually use creates a false
signal that clients rely on when computing trust.

This rule is the compliance-framework counterpart to analyzer rule I12
(Capability Escalation Post-Init). It produces an EvidenceBundle with
the structural disagreement so the per-framework reporter can surface
it with regulatory framing (EU AI Act Art.13 transparency).

## Real-world references

- **I12-MCP-Sentinel** — analyzer rule for capability escalation.
- **MCP-Spec-Init** — initialize handshake contract.
- **OWASP-MCP07** — Insecure Configuration.
- **Invariant-2025-CAPS** — documented incident where a server
  silently enabled sampling without declaring it, triggering
  client-side cost amplification.

## Lethal edge cases

1. **Sampling used, not declared** — server triggers inference
   callbacks without telling the client.
2. **Prompts used, not declared** — tool descriptions reference
   `prompts/get` semantics when the server never declared prompts.
3. **Resources referenced by URI in tool descriptions, not declared**.
4. **Every capability declared, most unused** — false advertising that
   defeats client-side capability-based access control.

## Evidence the rule must gather

- `context.declared_capabilities` — the declaration.
- `context.tools`, `context.prompts`, `context.resources`,
  `context.roots` — the observed surface.
- Cross-check: for each capability key, does the declaration agree
  with the observed presence/absence?

## Strategies (for runtime test generation)

- `trust-inversion`
- `privilege-chain`
- `shadow-state`

## Judge contract

A "fail" verdict is confirmed only if `facts.undeclared_uses` is
non-empty OR `facts.false_declarations` is non-empty AND the LLM's
`evidence_path_used` references one of the listed capability names.

## Remediation

Keep `capabilities` in the initialize response in sync with actual
server behavior. If a capability is not actually implemented, remove
it from the declaration; if it is used, declare it. Run the
capability-declaration-honesty rule in CI before publishing releases.

## Traceability (machine-checked)

rule_id: shared-capability-declaration-honesty
threat_refs:
- I12-MCP-Sentinel
- MCP-Spec-Init
- OWASP-MCP07
- Invariant-2025-CAPS
strategies:
- trust-inversion
- privilege-chain
- shadow-state
