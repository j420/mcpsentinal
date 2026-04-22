---
rule_id: F4
interface_version: v2
severity: low

threat_refs:
  - kind: spec
    id: MCP-Spec-2024-11-05
    url: https://modelcontextprotocol.io/specification/2024-11-05
    summary: >
      Original MCP specification (2024-11-05). The tools/list response
      MUST return an array of tool objects, and each tool MUST carry a
      `name` field. The `description` and `inputSchema` fields are
      recommended: AI clients use them to choose when to call the tool
      and how to fill its parameters. A nameless tool is a protocol
      violation; a tool without a description or an inputSchema is a
      spec-recommendation violation that materially degrades the
      client's ability to decide whether to invoke it safely.
  - kind: spec
    id: MCP-Spec-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26
    summary: >
      MCP specification 2025-03-26 — Streamable HTTP transport and the
      tool annotations surface (readOnlyHint, destructiveHint,
      idempotentHint, openWorldHint) are added. The initialize response
      gained `serverInfo.version` as a required-when-present field and
      `serverInfo.name` remains mandatory. Servers that omit
      serverInfo.version or ship a non-semver version string leave the
      client unable to detect protocol drift or correlate a finding to
      a deployed release.
  - kind: spec
    id: OWASP-MCP07-Insecure-Config
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 — MCP07 Insecure Configuration. Spec-deviation
      is a direct insecure-configuration signal: the protocol cannot
      make safety guarantees about fields the server does not fill in.
      Rules that check spec compliance feed directly into the MCP07
      posture a scanner reports back to the reviewer.
  - kind: paper
    id: MCP-Spec-Compliance-Audit-2026
    url: https://modelcontextprotocol.io/specification/changelog
    summary: >
      The MCP spec changelog records every required/recommended field
      addition from 2024-11-05 onward. F4 encodes the minimum three
      field classes relevant at scan time — tool.name (required),
      tool.description (recommended), tool.inputSchema (recommended) —
      to produce a low-severity compliance finding without over-claiming
      security impact. A compliance gap is a signal for deeper review,
      not a direct vulnerability.

lethal_edge_cases:
  - >
    Empty or whitespace-only tool name — the tool object exists in
    tools/list but `name` is "" or "   ". The MCP client enumerates
    the tool, the user-facing approval UI has nothing to render, and
    downstream tool-selection by the LLM becomes ambiguous. The rule
    must structurally distinguish "missing name" from "empty-string
    name" from "whitespace-only name" — all three are spec violations
    but carry different rationales.
  - >
    Tool registered without a description — `description` is null,
    undefined, or an empty string. The LLM must guess the tool's
    purpose from the name alone, which is the documented vector for
    tool-name-shadowing confusion (see A4). A tool named `update`
    could be a read or a destructive write; the spec-recommended
    description is what disambiguates.
  - >
    Tool has no inputSchema (null, undefined, or an object with no
    properties at all). The spec recommends inputSchema so clients
    can validate arguments before dispatching; absence means the AI
    client passes unvalidated free-form input. Rule must treat
    "inputSchema: {}" as acceptable (empty-parameter tool) but flag
    "inputSchema: null" or missing field.
  - >
    Wrong MCP protocol version string in initialize — a server
    returning `protocolVersion: "2024-10-07"` or a non-listed version
    tag indicates either a stale server or a fabricated version
    identifier. The rule emits a compliance finding so the reviewer
    can confirm the server was built against a real spec revision.
  - >
    Non-semver serverInfo.version — `version: "dev"` or
    `version: "latest"` satisfies the presence check but defeats the
    purpose (correlating a finding to a deployed release). The rule
    emits a low-severity finding when the version field exists but is
    not semver-shaped.

edge_case_strategies:
  - empty-name-structural-check
  - missing-description-check
  - missing-inputschema-check
  - protocol-version-validation
  - semver-shape-check

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - spec_field_class
  location_kinds:
    - tool
    - capability
    - initialize

obsolescence:
  retire_when: >
    The MCP specification becomes strict-schema-enforced at the
    transport layer — i.e. a tools/list entry missing `name` is
    rejected by the SDK itself before reaching the analyzer — AND
    the initialize handshake rejects servers whose protocolVersion
    field is not a published spec revision. Under those conditions
    F4 becomes a post-hoc duplicate of the transport's own validator.
---

# F4 — MCP Spec Non-Compliance

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any MCP server whose tool list has been enumerated by
the scanner — `context.tools`. The check is entirely metadata-driven
and does not require source code.

## What an auditor accepts as evidence

A compliance auditor (OWASP MCP07, ISO 27001 A.5.37 documented operating
procedures) will not accept a rule that says "looks non-compliant". They
will accept a finding that says:

1. **Structural proof** — the finding names the specific tool (a
   `Location` of `kind: "tool"`) AND the specific field class that is
   missing or malformed (empty name, missing description, missing
   inputSchema). Each field class is documented against a specific
   line of the spec (charter threat_refs above).

2. **Classification proof** — the finding enumerates which spec
   field class triggered it: (a) required-field missing
   (tool.name null / empty / whitespace), (b) recommended-field
   missing (tool.description null / empty), (c) recommended-field
   missing (tool.inputSchema null). The rule does NOT emit a single
   generic "spec violation" — each class is separately cited.

3. **Impact statement** — concrete description: the missing field
   prevents the AI client from making a safe dispatch decision. For
   `name` the impact is tool-selection ambiguity; for `description`
   it is capability-inference drift; for `inputSchema` it is
   unvalidated argument passthrough. The rule's severity is low
   because the spec gap is a signal, not a direct vulnerability —
   other rules (A1, B1, C1) catch the vulnerability itself.

## Why confidence is capped at 0.75

Spec-compliance heuristics carry inherent uncertainty:

- a server may intentionally omit a field to signal a capability
  negotiation (e.g. description-free tools returned only when the
  client declared `supportsDescriptions: false` — a future spec
  revision might introduce this);
- the spec itself evolves; today's "recommended" can become tomorrow's
  "required" or "deprecated", and the rule's static view of the spec
  lags behind the live document;
- the analyzer does not know the live protocol version negotiated by
  the handshake — it only sees the static tools/list response.

Capping at 0.75 preserves explicit room for these externalities. The
remaining 0.25 signals: "compliance gap detected, reviewer must
corroborate against the spec revision the server actually negotiated."
