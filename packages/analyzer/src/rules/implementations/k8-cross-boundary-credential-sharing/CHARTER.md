---
rule_id: K8
interface_version: v2
severity: critical
owasp: MCP05-privilege-escalation
mitre: AML.T0054
risk_domain: authentication

threat_refs:
  - kind: spec
    id: ISO-27001-A.5.17
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.17 (Authentication
      Information) requires authentication information (passwords,
      tokens, secrets) to be allocated, distributed, and used in a way
      that preserves confidentiality and prevents unauthorised use. A
      server that forwards an incoming bearer token to a downstream
      service distributes authentication information across a trust
      boundary the user never authorised — a direct A.5.17 violation.
  - kind: spec
    id: OWASP-ASI03
    url: https://genai.owasp.org/llmrisk/llm03-identity-privilege-abuse/
    summary: >
      OWASP ASI03 (Identity & Privilege Abuse) documents credential
      misuse as the #3 agentic-AI risk. The canonical failure:
      delegated permissions from a legitimately-approved MCP server
      propagate to a downstream service via credential forwarding,
      granting the downstream the same privileges the user granted the
      original server.
  - kind: spec
    id: OWASP-ASI07
    url: https://genai.owasp.org/llmrisk/llm07-insecure-inter-agent-communication/
    summary: >
      OWASP ASI07 (Insecure Inter-Agent Communication). Shared
      credentials between agents / services are the primary mechanism
      by which a compromise of one agent propagates to the rest of the
      ecosystem — the attacker pivots through the shared credential.
  - kind: paper
    id: cosai-mcp-t1-confused-deputy-2026
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP Threat Taxonomy T1 (Confused Deputy). Explicitly warns
      about MCP servers acting as OAuth proxies that pass upstream
      tokens to backends. The taxonomy recommends OAuth Token Exchange
      (RFC 8693) as the only acceptable cross-boundary delegation
      primitive — anything else is a shared-credential failure.

lethal_edge_cases:
  - >
    Bearer token forwarded via header — the MCP server reads
    `req.headers.authorization` and places it on the headers of an
    outbound fetch / axios / got call to a different origin. The
    credential is now held by the downstream service at full scope,
    violating the scoped-consent property of the original approval.
  - >
    Credential written to a shared store — the server reads an API key
    from process.env.API_KEY and publishes it to a cache / queue / KV
    (Redis SET, DynamoDB PutItem, sqs.SendMessage). Any other service
    with read access to the store now holds the credential,
    indistinguishable from legitimate holders.
  - >
    Credential returned in a tool response — the server includes the
    token in the MCP tool's output (result.content includes
    "Bearer ..."). The receiving AI client, any relay / logger /
    middleware in the path, and the eventual model all see the raw
    credential. A static rule must detect shaping the token into a
    returned value, not only direct network sends.
  - >
    Ambient-credential OAuth proxy — the server accepts an access token
    from the incoming request and replays it verbatim to a downstream
    MCP server. This is the canonical "confused deputy" OAuth problem:
    the downstream believes the upstream's user has authorised it, but
    the user never saw the downstream in the approval dialog.
  - >
    Secret flowing into a command-execution sink — the server exec()s
    a subprocess with the token in argv or stdin (`curl -H
    "Authorization: $API_KEY" ...`). The token is visible in the
    process table, the shell history, and any audit log that captures
    command arguments — a multi-boundary exposure even before the
    subprocess reaches the network.

edge_case_strategies:
  - header-credential-forward-detection
  - shared-store-write-detection
  - credential-in-tool-response
  - oauth-proxy-confused-deputy
  - exec-with-credential-argument

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - credential_source_identified
    - cross_boundary_sink_identified
    - no_token_exchange_observed
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Every MCP server supporting authenticated downstream delegation
    uses RFC 8693 Token Exchange exclusively (no raw-token forwarding)
    AND the MCP protocol requires clients to enumerate every
    delegation relationship in the approval dialog. At that point raw-
    token forwarding is structurally impossible and the rule's
    detection surface evaporates.
---

# K8 — Cross-Boundary Credential Sharing

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source that handles authentication
information (tokens, keys, passwords, secrets) and also performs
outbound communication (HTTP, queue publishing, process exec, MCP
client calls, tool responses).

## Distinct from L9 / K14

- L9 covers CI secret exfiltration (env var → log echo).
- K14 covers credential propagation via SHARED AGENT STATE (queue,
  scratchpad, vector store).
- K8 stays focused on the trust-boundary crossing — a credential that
  was scoped to one service reaches another one.

## What an auditor accepts as evidence

An ISO 27001 A.5.17 / CoSAI MCP-T1 auditor will accept:

1. **Source proof** — a `source`-kind Location at the credential load
   (`process.env.API_KEY`, `req.headers.authorization`, a read of a
   `.npmrc`/`.pypirc` / config.json token field, an OAuth access-
   token field destructured from the request body).

2. **Propagation proof** — a cross-tool / cross-file flow from the
   source to an outbound operation. Three accepted shapes:
   (a) AST taint from the environment source to a network sink
   (preferred), (b) assignment of the token to an object literal
   whose shape is an HTTP headers / Authorization field,
   (c) inclusion of the token in a tool-response `content` array.

3. **Sink proof** — a `sink`-kind Location at the cross-boundary
   operation: fetch / axios / got / http.request / mcp.client.callTool
   / redis.set / sqs.sendMessage / spawn / exec / tool-response-return.

4. **Mitigation check** — the rule reports whether the code uses
   RFC 8693 Token Exchange (identifier contains "token_exchange" /
   "tokenExchange" / "rfc8693"). Presence reduces confidence; absence
   is the worst case.

5. **Impact** — ASI07-class cross-agent compromise: any party holding
   the forwarded token can impersonate the user across every service
   the token covers.

## Why confidence is capped at 0.85

A server legitimately acting as an authenticated proxy for its OWN
identity (not the user's) performs similar-looking code shapes but is
not a K8 violation. The 0.85 cap reserves room for that ambiguity —
the static rule cannot always tell whether the token belongs to the
server or the caller.
