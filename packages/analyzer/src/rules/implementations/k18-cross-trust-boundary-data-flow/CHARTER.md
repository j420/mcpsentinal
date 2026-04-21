---
rule_id: K18
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T5
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI MCP threat taxonomy T5 — Inadequate Data
      Protection (cross-boundary transfers). Explicit requirement:
      sensitive data may not flow through a tool response without a
      classification-aware redaction step. Absence of the step is a
      T5 control gap regardless of whether the specific request, at
      this moment, leaks a specific secret.
  - kind: spec
    id: ISO-27001-A.5.14
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A 5.14 — Information transfer. The
      control requires documented policies + technical controls
      preventing unauthorised transfer. A tool response that carries
      `process.env.SECRET_KEY` to the AI client is an unauthorised
      transfer by construction; the client is a different trust zone.
  - kind: spec
    id: EU-AI-Act-Art-15
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      EU AI Act Article 15 — Cybersecurity. Requires appropriate
      protection of high-risk AI systems against confidentiality
      attacks. Server-side leaks into tool responses are a direct
      confidentiality-attack surface the regulator is entitled to
      expect protection against.
  - kind: paper
    id: OWASP-LLM06-SensitiveInfoDisclosure
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP Top 10 for LLM Applications — LLM06 Sensitive Information
      Disclosure. The LLM receiving secrets in tool responses (then
      potentially echoing them in downstream turns) is the archetypal
      LLM06 violation; K18 is the static detector for the server-side
      enabler.

lethal_edge_cases:
  - >
    Sensitive value is read via a call the rule has never seen —
    e.g. `vault.getCredential()` rather than `process.env.FOO`.
    A vocabulary keyed on `process.env.*` misses it. The rule
    classifies any CallExpression / PropertyAccess whose receiver
    OR method name contains a sensitivity token (secret, credential,
    token, key, password, vault, kms, sensitive) as a sensitive
    source.
  - >
    Value renamed once between source and sink — `const s =
    process.env.TOKEN; const out = { access: s }; return out`. A
    one-step check would miss it. The rule propagates the taint
    across VariableDeclaration chains (direct assignment, object-
    property composition) within the enclosing function.
  - >
    Redaction function applied to a different variable — `const
    safe = redact(otherValue); return { secret: tokenVar }`. A
    "redact present" check would false-negative. The rule demands
    the redactor's argument is the SAME identifier (or a
    descendant-reachable identifier) as the value reaching the
    external sink.
  - >
    Sensitive parameter name vs safe value — a function parameter
    called `password` is actually the hash, not the plaintext. The
    rule cannot disambiguate; it fires and the auditor reviews.
    Acknowledged false-positive window — confidence is adjusted
    downward when the sensitivity signal is only the parameter
    name.
  - >
    Test harness constructs sensitive-looking data for assertions —
    `const password = "abc"; return password`. The structural test-
    file detector (vitest / jest / mocha imports + describe/it
    top-level) suppresses all findings in test files.

edge_case_strategies:
  - sensitivity-token-set          # callee / receiver / identifier tokenisation
  - single-function-taint-walk     # propagate through assignments and object composition
  - redactor-same-argument         # redactor must see the tainted identifier
  - param-name-sensitivity-downweight
  - structural-test-file-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - sensitive_source_kind
    - external_sink_reached
    - no_redactor_on_tainted_value
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP introduces a first-class "dataClassification" protocol
    primitive that tags every response field with its sensitivity
    band, and clients enforce classification-aware rendering — at
    which point server-side redaction becomes a protocol invariant
    and K18's static detection moves to the client layer.
---

# K18 — Cross-Trust-Boundary Data Flow in Tool Response

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server handlers that read sensitive values
(env vars, credential stores, private file paths, sensitivity-
named identifiers) AND emit a tool response.

## What an auditor accepts as evidence

A CoSAI T5 / ISO 27001 A.5.14 auditor will not accept "there was
no redactor in the file". They will accept a rule that:

1. Names the **sensitive source** — a concrete CallExpression /
   PropertyAccess / parameter with a `source`-kind Location — and
   classifies it (`env-secret`, `credential-call`, `sensitive-path`,
   `sensitive-param`).

2. Names the **external sink** the taint reaches — a ReturnStatement
   or a response-emitting call with a `source`-kind Location.

3. Reports the **redactor mitigation** against the tainted identifier
   specifically — not any redactor in scope. A redactor applied to a
   different identifier is PRESENT but `sameVariable=false` and is
   downgraded accordingly.

4. States the **impact** concretely — the LLM receives the secret in
   its context window, may echo it in subsequent turns, and any
   downstream tool or log capturing the response reveals the secret
   at its own layer. OWASP LLM06 names this the archetypal disclosure
   pattern.

## Confidence cap — 0.88

The strongest proof is a full within-function source→sink taint chain
with a same-variable redactor check. Cross-module flows and
middleware-based redactors are invisible to a file-scope walker. The
0.88 cap reflects that uncertainty.
