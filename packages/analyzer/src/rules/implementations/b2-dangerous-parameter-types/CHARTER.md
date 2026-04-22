---
rule_id: B2
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP03
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP03 Command Injection. Parameter names
      like "command", "cmd", "shell", "exec", "script" advertise a
      direct path to an execution sink. The AI reads the name to
      decide what to put in the field; a free-text name invites
      shell metacharacters.
  - kind: spec
    id: OWASP-MCP05
    url: https://owasp.org/www-project-mcp-top-10/
    summary: >
      OWASP MCP Top 10 — MCP05 Privilege Escalation. Parameters named
      "path", "file_path", "uri", "url" without structural validation
      allow path traversal and SSRF. The name itself is a high-risk
      signal and should trigger extra scrutiny.
  - kind: paper
    id: CYBERARK-FSP-2025
    url: https://www.cyberark.com/resources/threat-research-blog/full-schema-poisoning
    summary: >
      CyberArk Labs (2025) "Full Schema Poisoning" research. Parameter
      names are a first-class attack surface — LLMs consult the name
      to select which tool to call, so "command" names advertise a
      command-execution tool to the model's intent classifier.

lethal_edge_cases:
  - >
    Parameter "cmd" — classic shell-command name. The AI fills it
    with whatever the user asked for (possibly with shell syntax).
  - >
    Parameter "sql" — SQL injection primitive; the AI puts a SQL
    query there, including user-controlled fragments.
  - >
    Parameter "code" — generic RCE primitive; the AI puts arbitrary
    code that the server's eval/exec handler will run.
  - >
    Parameter "template" — SSTI primitive. Jinja/EJS/Handlebars-style
    template strings from the AI flow into a template engine.

edge_case_strategies:
  - dangerous-name-catalogue
  - exact-match-after-normalisation

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - dangerous_param_name
  location_kinds:
    - tool

obsolescence:
  retire_when: >
    MCP best-practice guidance deprecates parameter naming in favour
    of semantic type annotations (e.g. "execution-target", "file-path").

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# B2 — Dangerous Parameter Types

Checks every parameter name in a tool's schema against a typed
catalogue of dangerous name tokens. Matches drive the finding.
