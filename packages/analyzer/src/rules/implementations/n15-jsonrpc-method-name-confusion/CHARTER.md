---
rule_id: N15
interface_version: v2
severity: critical
owasp: MCP05-privilege-escalation
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: JSON-RPC-2.0-Method-Names
    url: https://www.jsonrpc.org/specification#request_object
    summary: >
      JSON-RPC 2.0 §4 defines method names as strings. Method names
      beginning with "rpc." are reserved but ordinary names are a
      free-form namespace — the receiving server is responsible for
      routing method lookups to the correct handler. When method names
      are routed via dynamic dispatch from user input, or when non-
      canonical names confusable with canonical MCP methods are
      registered, the routing layer itself becomes an injection surface.
  - kind: paper
    id: Method-Name-Typosquat-Research
    url: https://invariantlabs.ai/blog/method-name-attacks
    summary: >
      Invariant Labs (2026) catalogued method-name confusion attacks
      against MCP servers. Two concrete vectors: (a) user-input
      dispatched as method name (the most dangerous case — arbitrary
      handler invocation), and (b) handler registration under a name
      that visually / semantically resembles a canonical method,
      fooling the client's allowlist.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      Method-name confusion is AML.T0054 at the RPC layer: adversary
      influences which handler runs by manipulating the name string.
      Where description injection changes CONTENT, method-name
      confusion changes ROUTING — a strictly more severe primitive.

lethal_edge_cases:
  - >
    User input used directly as the JSON-RPC method name. `dispatch[req.
    method]`, `handlers[params.op]`, `route[body.name]` patterns let
    an attacker invoke any registered handler regardless of the
    client's intent. This is the top-severity form of the class.
  - >
    Handler registered under a name Levenshtein-close to a canonical
    method ("tools/Call" vs "tools/call", "tools/call2" vs "tools/call",
    Unicode-homoglyph variants like "tоols/call" with Cyrillic 'о').
    The client's method allowlist may miss the imposter; the server
    accepts either.
  - >
    Dynamic dispatch via property access. `server[req.method](req.
    params)` treats method names as JavaScript property names. If the
    method name contains `__proto__` or `constructor`, prototype
    pollution becomes reachable from the RPC layer. Cross-reference
    C10 (prototype pollution).
  - >
    Registration of spec-reserved names (prefix "rpc.") or names that
    shadow built-in method names ("toString", "valueOf"). These names
    pass the server's routing layer but cause confused-deputy issues
    at later stages (JSON serialisation, Object.keys listing).

edge_case_strategies:
  - user-input-as-method-name-scan
  - levenshtein-near-canonical-method-scan
  - dynamic-dispatch-property-access-scan
  - reserved-name-shadow-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - method_name_confusion_type
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP SDKs ship with a method-registration API that rejects non-
    canonical names, AND client-side allowlists normalise method
    strings (trim, lowercase, strip Unicode confusables) before
    comparison. Until then, server-side registration discipline is
    the defence.
---

# N15 — JSON-RPC Method Name Confusion

Uses Levenshtein similarity (shared `analyzers/similarity.ts` wave-1
primitive) to compare observed handler registrations against the
canonical MCP method catalogue. Confidence cap 0.88.
