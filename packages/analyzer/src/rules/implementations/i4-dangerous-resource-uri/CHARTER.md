---
rule_id: I4
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-53109
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53109
    summary: >
      Anthropic filesystem MCP server root-boundary bypass — a declared
      root was evaded by path-traversal in resource URIs. CVE-2025-53109
      is the canonical real-world precedent for why MCP clients must
      reject dangerous URI schemes and traversal sequences in the
      resource surface.
  - kind: cve
    id: CVE-2025-53110
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53110
    summary: >
      Companion filesystem MCP server path-traversal CVE disclosed with
      CVE-2025-53109. Both demonstrate that URI-level content controls
      in the MCP protocol surface are load-bearing: a resource whose
      scheme is file:// or whose path contains ../ gives the MCP client
      access to data outside its intended scope.
  - kind: spec
    id: MCP-Resources-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/resources
    summary: >
      MCP 2025-03-26 specification for the resources/read endpoint.
      Clients that resolve resource URIs must treat the URI as
      attacker-influenced when the resource declaration originates
      from an untrusted server; dangerous schemes and traversal
      markers are exactly the abuse surface the spec does NOT mandate
      a client must refuse.

lethal_edge_cases:
  - >
    file:// URI with an absolute path outside the declared roots — the
    MCP client treats the resource as readable because the scheme is
    supported, but the path resolves to /etc/passwd, ~/.ssh/id_rsa, or
    the Kubernetes projected service-account token mount. Declared
    roots do NOT automatically constrain file:// URIs unless the
    client enforces the root boundary, and CVE-2025-53109 proved that
    the bundled Anthropic filesystem server did not.
  - >
    data:text/html;base64,...  URIs — the resource body is inline
    attacker-controlled content. A client that renders the resource
    (browser-style panels, markdown previews) executes whatever HTML /
    JS the server encoded. No network call is made, so network-layer
    egress controls never see the exfil path.
  - >
    javascript: / vbscript: URIs — any MCP client with a web-capable
    rendering surface executes the payload in the client's origin. The
    server does not need a sink at all; the URI IS the sink.
  - >
    Path-traversal (../, %2e%2e, %252e%252e, fullwidth ．．/) in the URI
    of an otherwise-benign scheme (https://server/api/../../../etc/…).
    Normalisation differs between the server's declared-URI check and
    the client's final filesystem/HTTP resolver — the gap is the
    exploit.
  - >
    Resources whose URI is constructed dynamically from a tool
    parameter at runtime — the static scan sees an https:// template,
    the actual fetch resolves into a data: or file: URI under
    attacker control. The charter emits the finding against the
    literal scheme observed at scan time AND flags parameter-derived
    URIs for dynamic review.

edge_case_strategies:
  - scheme-catalogue-match
  - traversal-marker-match
  - root-containment-warning
  - render-surface-exploit-path
  - dynamic-uri-construction-flag

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - dangerous_scheme_confirmed
    - charter_confidence_cap
  location_kinds:
    - resource

obsolescence:
  retire_when: >
    MCP clients uniformly refuse to resolve resources whose scheme is
    outside a documented allowlist (https + the MCP stdio transport
    tokens), AND the MCP specification mandates root-containment
    checking as a MUST-level client requirement. Until both ship, I4
    remains critical.

mutations_survived: []
mutations_acknowledged_blind: []
---

# I4 — Dangerous Resource URI

**Author:** Senior MCP Protocol Threat Researcher persona (adversarial).
**Applies to:** any MCP server that declares `resources` with URIs.

## Why this is a separate rule

I4 is the companion of I11 (Over-Privileged Root). I11 checks the
filesystem scope the SERVER declares; I4 checks the INDIVIDUAL URIs
inside the resource list. An attacker who controls the server
definition can put a scheme or traversal marker in a single resource
that bypasses any root-level check — because roots are a scope
declaration, not a URI filter.

Matched schemes and traversal markers come from
`_shared/protocol-shape-catalogue.ts` (`DANGEROUS_URI_SCHEMES`,
`TRAVERSAL_MARKERS`). Every entry has a false-positive fence — a
legitimate https resource with a path containing the token "example"
is a documentation link, not an exploit.

## Confidence cap

Capped at **0.92**. URI scheme + traversal detection is effectively
boolean (the scheme is present or it is not), so the cap is high.
The 0.08 gap accounts for: (a) schemes that are benign in some
client contexts but dangerous in others, and (b) Unicode-form
traversal markers that a strict byte check might mis-attribute.
