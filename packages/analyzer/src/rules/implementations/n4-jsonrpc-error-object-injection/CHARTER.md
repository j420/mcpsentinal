---
rule_id: N4
interface_version: v2
severity: critical
owasp: MCP01-prompt-injection
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: JSON-RPC-2.0
    url: https://www.jsonrpc.org/specification#error_object
    summary: >
      JSON-RPC 2.0 §5 defines the error object with three fields —
      `code`, `message`, and optional `data`. The spec does NOT require
      clients to sanitise either field before displaying or processing
      it. `data` is explicitly defined as "additional information about
      the error" and is commonly stringified into logs, surfaced to
      humans, or — in MCP's case — routed into the model's reasoning
      window as part of the tool-call error surface.
  - kind: paper
    id: CyberArk-FSP-2025
    url: https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning
    summary: >
      CyberArk's Full Schema Poisoning research (2025) generalised the
      tool-poisoning threat model beyond description injection and
      called out error-object fields as an equivalent injection channel.
      Clients that display or forward `error.message` / `error.data` do
      so without the same sanitisation they apply to `tool.description`,
      so the error path is the cheapest injection surface once an
      attacker can coerce the server into raising an error with
      controllable content.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      The error-path variant of prompt injection is AML.T0054 in a
      different serialisation. The exfil path is identical to a
      description-level injection; only the envelope differs. Treating
      `error.message` with lower rigor than `tool.description` is the
      architectural mistake the rule detects.

lethal_edge_cases:
  - >
    User-controlled input concatenated into `error.message`. The server
    echoes `req.params.name` into an error message (e.g. `throw new
    Error(\`Unknown tool: ${req.params.name}\`)`); an attacker picks a
    tool name that contains a prompt-injection payload and the payload
    lands in the model's context as part of the error display. No
    sanitiser is triggered because the path is the error surface, not
    the description surface.
  - >
    Stack trace serialisation. The server returns `err.stack` in
    `error.data`. Stack frames include file paths, line numbers, and
    occasionally stringified arguments — the latter can carry adversary
    bytes verbatim from the failing call. This is M9-adjacent
    (credential exposure) but structurally the same channel N4 targets.
  - >
    User input propagated through Error construction. A library throws
    an Error whose message field is constructed from `body` / `params` /
    `query`. The try/catch wraps the throw and re-emits as an
    `error.data` object. This form is harder to see because the
    attacker-reachable input is several call sites upstream of the
    response.
  - >
    Error helper that stringifies the entire input object into `.data`.
    Tools that log "the failing request was: ${JSON.stringify(req)}"
    carry the whole user-payload into the error surface. Attackers
    plant payloads in unused fields knowing the error path serialises
    everything.

edge_case_strategies:
  - user-input-to-error-message-scan
  - stack-trace-in-error-data-scan
  - error-constructor-user-input-scan
  - full-request-stringify-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - user_input_to_error_path
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP client spec mandates that `error.message` and `error.data` are
    NEVER forwarded into the model's reasoning context, AND all
    mainstream client implementations redact or opaque-ify these fields
    before display. Until then, the server-side avoidance is the only
    defence.
---

# N4 — JSON-RPC Error Object Injection

**Author:** Senior MCP JSON-RPC / Transport Security Engineer (dual persona).

## Threat narrative

The JSON-RPC error object is the third channel by which a server can
convey content to the client — alongside tool responses and log
notifications. Clients display, log, and often forward error content
into the model's reasoning window, and they do so without applying the
sanitisation rigor they give to `tool.description`. That asymmetry is
the threat.

N4 detects the server-side code shape where user-controlled input flows
into `error.message` or `error.data` without sanitisation. It is a
structural scan — not a prose check — on source-code line text. Zero
regex literals; the lexicons live in `./data/error-surfaces.ts`.

## Confidence cap

**0.82**. The rule observes the source line; it does not execute the
error path. A reviewer may find the error never fires in practice.
