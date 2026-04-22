---
rule_id: N9
interface_version: v2
severity: critical
owasp: MCP01-prompt-injection
mitre: AML.T0054
risk_domain: protocol-transport

threat_refs:
  - kind: spec
    id: MCP-Logging-Notifications
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/utilities/logging
    summary: >
      MCP `notifications/message` is the spec-sanctioned channel by which
      the server streams structured log events to the client. The spec
      defines `level` and `data` fields but does not require clients to
      sanitise `data` before forwarding it into audit trails or agent
      reasoning context. Log injection here has the unique property of
      bypassing ordinary tool-description scanning because the envelope
      is a notification, not a tool response.
  - kind: spec
    id: ISO-27001-A.8.15
    url: https://www.iso.org/standard/27001
    summary: >
      ISO 27001 A.8.15 mandates integrity of audit logs. When MCP
      `notifications/message` content is user-influenced without
      sanitisation, the attacker can forge log lines that impersonate
      system events. This rule is framework-linked through K20
      (insufficient audit context) but targets a different vector: the
      protocol surface, not the logging library.
  - kind: paper
    id: Log-Forging-OWASP
    url: https://owasp.org/www-community/attacks/Log_Injection
    summary: >
      OWASP Log Injection research predates MCP but applies directly:
      any pipe that carries user bytes into a log that is later parsed /
      displayed by a privileged consumer is an injection channel. MCP
      notifications/message is that channel at the protocol layer.

lethal_edge_cases:
  - >
    Tool handler calls `sendLogMessage` with `req.params.arguments.foo`
    directly as the `data` field. Attacker-chosen bytes become log
    content; a client that forwards log content into agent context
    propagates the payload.
  - >
    Python / Node `logging.info(f"processing {req.params.name}")` style
    log line that is ALSO plumbed through the MCP logging notification
    emitter. User bytes become log bytes become notification bytes.
  - >
    Logger middleware attaches every request body to the log context
    automatically. The attacker never needs to select a specific field;
    the serialiser emits the whole payload under `data`. Cross-reference
    K20 (insufficient audit context) and K2 (audit trail destruction) —
    different symptom surface, same class.
  - >
    Server emits `notifications/message` directly with a user-controlled
    `level` field. The level is processed by clients to decide whether
    to escalate the log (e.g. level=error → pager). Attacker escalates
    or suppresses at will.

edge_case_strategies:
  - sendlogmessage-user-input-scan
  - logger-info-user-input-scan
  - logger-middleware-body-attach-scan
  - notifications-message-level-from-user-scan

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - user_input_to_log_path
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP clients universally strip / escape LLM-significant bytes from
    `notifications/message.data` before forwarding to agent context or
    audit store. Until then, server-side avoidance is primary.
---

# N9 — MCP Logging Protocol Injection

Structural. Skips test files. Confidence cap 0.82. Lexicon in
`./data/log-surfaces.ts`.
