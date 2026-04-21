---
rule_id: K12
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T4
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI MCP threat taxonomy T4 — Tool Response
      Integrity. Specifies that tool responses must not carry content
      the client will interpret as executable. Embedded eval / Function /
      script tag / javascript: URIs violate the control by construction.
  - kind: spec
    id: OWASP-ASI02
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI02 — Tool Poisoning. Names
      response-level code execution as the archetype: an attacker who
      influences tool output can hijack the client's execution via
      embedded executable constructs.
  - kind: spec
    id: MAESTRO-L3
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 3 (Communication) requires that every inter-component
      message be treated as untrusted until sanitized. Tool responses are
      inter-component messages; embedding executable constructs violates
      L3 regardless of whether the producer believes the content is safe.

lethal_edge_cases:
  - >
    Dynamic import as data: `return { loader: import(userPath) }`. The
    ImportKeyword CallExpression is distinct from a normal
    CallExpression; the rule handles it via ts.SyntaxKind.ImportKeyword
    detection. A detector that matches CallExpression by name misses this.
  - >
    Inline event handler in an HTML-like string: `<a href="#"
    onclick="alert(1)">` returned as a response body. The `onclick`
    attribute is an executable primitive. The rule scans string literals
    for `on<event>=` via a character walker (no regex).
  - >
    data:text/html URI carrying a script: `data:text/html,<script>…</script>`.
    Encoded as a string in a response, interpreted as a navigable
    document by the client. The rule recognises `data:text/html` as
    a distinct marker from `javascript:`.
  - >
    Sanitizer in scope but applied to a DIFFERENT value — the function
    calls `DOMPurify.sanitize(otherVar)` in its body but returns
    `userHtml` without sanitisation. The rule records a PRESENT
    mitigation (sanitizer seen) but downstream reviewers must confirm
    applicability. Acknowledged false-negative window.
  - >
    `res.send` not flagged because it's called on `response` instead of
    `res`. The rule covers receiver vocabulary: res, response, resp,
    reply, ctx. An MCP-specific wrapper like `mcpRes.send` is NOT in
    the vocabulary; teams using non-standard wrappers need to extend
    RESPONSE_RECEIVERS.

edge_case_strategies:
  - exec-call-identifier-set      # eval / require bare calls
  - new-expression-identifier-set # new Function
  - import-keyword-ast            # dynamic import()
  - string-marker-substring       # <script / javascript: / data:text/html
  - inline-event-handler-scan     # on<event>= character walk
  - sanitizer-scope-check         # walk enclosing function body for sanitizer call
  - response-receiver-method-pair # res.send / response.json / ctx.body
  - structural-test-file-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - exec_eval_call | exec_new_function | exec_require_call | exec_dynamic_import | exec_script_tag_string | exec_javascript_uri_string | exec_data_html_uri_string | exec_inline_event_handler_string
    - no_sanitizer_in_scope
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP spec mandates that clients sandbox every response payload (no
    direct rendering of HTML, no automatic evaluation of embedded code
    constructs) — at which point the detection moves to the client
    enforcement layer.
---

# K12 — Executable Content in Tool Response

Zero regex. Structural AST detection of executable primitives crossing the
tool-response boundary without an observed sanitizer in the enclosing
function scope. See `CHARTER.md` frontmatter for the full contract.
