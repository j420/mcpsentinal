---
rule_id: K14
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-ASI03
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI03 — Identity & Privilege Abuse.
      An agent must not acquire credentials it was not granted. Writing a
      bearer token, API key, or session cookie to a state surface that any
      other agent reads is a direct ASI03 violation.
  - kind: spec
    id: OWASP-ASI07
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP ASI07 — Insecure Inter-Agent Communication. Shared scratchpads,
      vector stores, and working-memory tables are inter-agent channels.
      Embedding credentials in those channels lets a downstream agent
      impersonate the user without an explicit grant.
  - kind: spec
    id: MAESTRO-L7
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 7 (Agent Ecosystem) — credential boundaries are
      per-agent. Cross-agent credential propagation collapses the layer.
  - kind: paper
    id: InvariantLabs-CrossAgentMCPMemory-2026
    url: https://invariantlabs.ai/blog/cross-agent-mcp-memory-pollution
    summary: >
      Invariant Labs (Jan 2026) "Cross-agent pollution via shared MCP
      memory." Demonstrates a worker agent writing an OAuth bearer token
      into a LangGraph shared scratchpad, after which a downstream agent
      replays the token against an unrelated tool. The attack works because
      MCP shared-state tools accept any string and treat it as opaque data.

lethal_edge_cases:
  - >
    Credential transformed before write: `sharedStore.set("ctx",
    Buffer.from(token).toString("base64"))`. Substring matching on the
    raw call site sees an encoder, not a credential. Taint must follow
    the value through the encoder back to its credential origin.
  - >
    Alias binding: `const s = sharedStore; s.set({ token })`. A detector
    that only knows the literal name `sharedStore` misses this. The
    rule resolves single-step variable aliases for shared-state receivers
    before classifying the call.
  - >
    Cross-function flow: helper `function persist(t) { sharedStore.set(t); }`
    is called from a handler that owns a credential variable. The detector
    must walk a call graph hop — argument-of-helper carrying a tainted
    credential identifier becomes the sink-receiver.
  - >
    Mock / placeholder values that look like credentials but are literals
    such as `"REPLACE_ME"`, `"<token>"`, `"xxxx"`, `"YOUR_API_KEY"`.
    The rule must NOT fire on these — confidence factor that downgrades
    when the right-hand side is a single string literal matching a
    placeholder vocabulary.

edge_case_strategies:
  - encoder-passthrough-taint
  - alias-binding-resolution
  - cross-function-helper-walk
  - placeholder-literal-suppression

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - credential_identifier_observed
    - shared_state_sink_observed
    - no_redaction_in_scope
    - charter_confidence_cap
  location_kinds:
    - source
    - tool
    - parameter
    - capability

obsolescence:
  retire_when: >
    The MCP spec adds protocol-level credential redaction in tool I/O
    serialisation (a `sensitive: true` schema flag that the runtime
    strips before any cross-agent state write), at which point shared
    memory cannot carry raw credentials regardless of caller intent.
---

# K14 — Agent Credential Propagation via Shared State

A multi-agent ecosystem is a credential federation only when every agent
proves its grant. The moment Agent A writes a token into a state surface
Agent B reads, the federation collapses into a single principal whose
authority is the union of every agent that has ever touched the store.

This rule names the static enabler of that collapse: a credential-bearing
identifier flowing into a cross-agent state-write call (vector store /
scratchpad / shared memory / working-memory cache / agent-to-agent message
bus) without an observed redaction step in the same lexical scope.

It is a flow rule. The minimum chain is source → propagation → sink with
both mitigation status (redactor seen / not seen) and impact recorded —
five links. Pure structural detection of "credential variable name" or
"shared-state object name" is insufficient; the chain must connect the
two through observed program structure.

Confidence is capped at 0.88. A runtime redaction layer (logging
formatter, store middleware, scrubbing proxy) is invisible to static
analysis. The cap is recorded as the `charter_confidence_cap` factor.

See the frontmatter for the four lethal edge cases and the named
strategies that handle them — every strategy name appears as a
constant or a branch label in `index.ts` and `gather.ts`.
