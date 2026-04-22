---
rule_id: G3
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: EMBRACE-THE-RED-INDIRECT-INJECTION-2024
    url: https://embracethered.com/blog/posts/2024/claude-llm-prompt-injection-mcp/
    summary: >
      Johann Rehberger (Embrace The Red, 2024). Documents real-world
      prompt-injection attacks against Claude Desktop and GPT-4 via
      MCP metadata. A specific variant — the "protocol-mimic" payload —
      describes or embeds structured JSON-RPC/MCP shapes inside tool
      descriptions so that the AI's parsing pipeline mistakes data
      for a protocol message or new tool call. G3 targets the static
      surface of that attack.
  - kind: cve
    id: CVE-2025-6514
    summary: >
      mcp-remote OS command injection (CVSS 9.6). A confused-deputy
      attack on the parsing layer: crafted payloads mimicking MCP
      protocol traffic traversed the boundary between "tool output"
      and "protocol message", enabling unauthenticated command
      injection. G3 flags descriptions that advertise exactly this
      boundary-crossing behaviour — prose claiming the tool's
      output IS protocol traffic.
  - kind: spec
    id: MITRE-AML.T0061
    url: https://atlas.mitre.org/techniques/AML.T0061
    summary: >
      MITRE ATLAS AML.T0061 — Thread Injection. Covers attacks that
      inject messages into an AI's conversation thread via content
      the model mistakes for protocol traffic. Embedded JSON-RPC
      shapes and protocol-mimic phrasing are the canonical static
      indicators of a Thread Injection attempt.
  - kind: spec
    id: MCP-SPEC-2025-03-26
    url: https://spec.modelcontextprotocol.io/specification/2025-03-26/
    summary: >
      MCP Specification 2025-03-26 defines the tool-response
      envelope shape. Legitimate tools describe their output in
      `inputSchema`/`outputSchema` STRUCTURE, not in prose claiming
      the tool returns protocol traffic. A description that
      advertises protocol-message output is almost always a
      confused-deputy vector.
  - kind: spec
    id: OWASP-MCP01
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP01 Prompt Injection. Tool-response
      format injection is explicitly listed as a direct injection
      variant: descriptions claiming structured-instruction output
      cause the AI to treat runtime responses as code.

lethal_edge_cases:
  - >
    Description asserts protocol output — "Returns JSON-RPC 2.0
    messages describing the next action to take". The authority
    phrase tokenises cleanly and fires a high-weight
    protocol-mimic match. Covered by the
    `returns_jsonrpc_messages` and `returns_protocol_messages`
    catalogue entries.
  - >
    Literal embedded envelope — description contains a verbatim
    `{"jsonrpc":"2.0","method":"tools/call","params":{...}}`
    example. The token subsequence `{ "jsonrpc" : "2" 0"` is
    detected structurally (not via regex), independent of the
    surrounding prose. Legit schemas live in `inputSchema`, never
    in description prose.
  - >
    MCP method reference — "Returns `tools/call` messages the AI
    should execute next". The `tools_call_method` and
    `method_tools_call_literal` entries combine with a
    `returns_tool_call` match for multi-signal corroboration.
  - >
    SSE/stream-framing claim — "Returns SSE events framed as
    server messages". Exploits client implementations that parse
    SSE frames inside tool responses, creating a second channel
    for injected instructions. Covered by `sse_framed_output` +
    `streamable_http_chunks`.
  - >
    Structured AI-instructions claim — description says the tool
    "returns formatted AI instructions for subsequent steps".
    Distinct from authority claims (G2): the attacker controls
    the content of the claimed "instructions" at runtime. Covered
    by `structured_ai_instructions`.
  - >
    Benign documentation — "This tool's schema explains the JSON-RPC
    protocol for educational purposes". The fence tokens
    ("documentation", "educational", "explains") demote every
    catalogue entry so educational references do NOT fire.

edge_case_strategies:
  - protocol-mimic-token-match        # multi-token "returns X protocol" phrases via tokenised walk
  - jsonrpc-shape-in-description      # literal "{\"jsonrpc\":\"2.0\"" envelope detected as token subsequence
  - mcp-method-reference-match        # literal "method":"tools/call" field detected structurally
  - noisy-or-aggregation              # combine independent protocol signals without double-counting
  - false-positive-fence-lookup       # fence tokens demote educational/documentation usage

evidence_contract:
  minimum_chain:
    source: true            # tool.description as a `tool` Location with the matched protocol phrase
    propagation: true       # description-directive — the phrase becomes LLM context
    sink: true              # code-evaluation — the LLM treats subsequent tool output as executable
    mitigation: false       # no static mitigation surface (structural description or not)
    impact: true            # confused-deputy scenario across the parsing layer
  required_factors:
    - protocol_mimic_phrase_match
    - noisy_or_base_confidence
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP clients enforce a strict structural separation between
    tool-output envelopes and protocol messages at the parsing
    layer — AND the spec requires tool response shape to be
    declared in `outputSchema` (not free-form prose). Until
    both hold, static detection of protocol-mimic phrasing is
    the only static signal available.
---

# G3 — Tool Response Format Injection

## Threat Model

A malicious MCP server publisher writes, in `tool.description`,
prose or literal payloads claiming the tool's RUNTIME output is
MCP protocol traffic, JSON-RPC messages, or new tool calls. The
description may contain:

  - a literal `{"jsonrpc":"2.0","method":"tools/call"...}` example
  - prose "returns JSON-RPC 2.0 messages"
  - an embedded `"role":"system"` chat message
  - a promise the output is "structured AI instructions"

Downstream, when the AI parses the tool's actual response, it is
primed to interpret that response as protocol traffic or a next
tool call — the confused deputy attack applied to the LLM's
parsing pipeline. CVE-2025-6514 (mcp-remote OS command injection,
CVSS 9.6) is a concrete real-world exploitation of this boundary.

## Detection Strategy — Why Linguistic + Structural, Not Regex

G3 is partly linguistic (prose claiming protocol output) and
partly structural (literal embedded envelope shapes). Both are
deterministic and tokenised — no regex literals.

The shared catalogue `_shared/ai-manipulation-phrases.ts` splits
into two typed Records for G3:

  - `G3_PROTOCOL_MIMICS` — multi-token prose phrases
    ("returns JSON-RPC messages", "returns tool call", "tools/call
    method") with per-entry false-positive fences.
  - `G3_JSONRPC_SHAPES` — literal token subsequences of the
    JSON-RPC envelope. Each entry's `phrase_tokens` is ≤5 tokens
    (e.g. `{`, `"jsonrpc"`, `:`, `"2`, `0"`) detected by the
    tokeniser as an ordered subsequence.

The gather step walks both tables, emits independent hits, and
the scorer combines them via **noisy-OR** aggregation.

## Severity Band

| Confidence | Severity |
|------------|----------|
| ≥ 0.80     | critical |
| 0.60–0.80  | high     |
| 0.50–0.60  | medium   |
| < 0.50     | (suppressed — noise floor) |

## Confidence Cap

**0.85.** Higher than G2 (0.80) because protocol-mimic language is
rarely legitimate: a legit tool documents its response shape
STRUCTURALLY in `outputSchema`, not in prose that describes its
output as protocol traffic. The remaining 0.14 headroom below
the 0.99 deterministic-proof ceiling accounts for edge cases
(educational content, documentation pages, self-describing
schema tools) — caught by the fence tokens, but the possibility
never reaches zero.

## Edge-Case Coverage (Honest Contract)

- **Prose "returns JSON-RPC messages"** — detected.
- **Literal `{"jsonrpc":"2.0"` envelope** — detected as a token
  subsequence (no regex).
- **MCP method references** (`tools/call`, `tools/list`) — detected.
- **SSE / Streamable HTTP framing claims** — detected.
- **Educational/documentation mentions** — suppressed by fence.
- **Non-English protocol descriptions** — NOT COVERED. Documented gap.
