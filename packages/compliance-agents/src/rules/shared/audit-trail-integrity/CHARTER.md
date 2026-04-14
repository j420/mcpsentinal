# Rule Charter: audit-trail-integrity

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** EU AI Act Art.12, OWASP MCP09, CoSAI T12, MAESTRO L5

## Threat model

A high-risk MCP server has destructive or sensitive tools but no
structural audit logging. When the server is exploited, there is no
forensic trail. EU AI Act Article 12 requires high-risk AI systems to
"automatically record events ('logs') over the duration of the system's
lifetime to ensure traceability" — an MCP server without a structured
audit sink is non-compliant by definition.

The lethal pattern is the absence of any tool-invocation log AND the
presence of at least one tool that mutates state.

## Real-world references

- **EU AI Act Art.12** — record-keeping for high-risk AI systems.
- **CoSAI MCP-T12** — audit completeness threat category.
- **OWASP MCP09** — Logging & Monitoring failures.
- **ISO 27001 A.8.15** — logging requirements.

## Lethal edge cases

1. **Mutating tools with no log call in their source path.**
2. **Logs captured but written to stdout only** — ephemeral, lost on
   container restart.
3. **Logs without tool name + caller identity + timestamp.**
4. **A "log" call that points at /dev/null** or a buffer never flushed.
5. **Tools that explicitly delete or truncate the log file.**

## Evidence the rule must gather

- Capability graph nodes that mutate state (`writes-data`,
  `executes-code`, `destructive`, `accesses-filesystem` with write
  semantics).
- Source-code presence of structured logging emission (audit log
  function calls). Detected via taint-AST sink scan over the source
  files map.
- Whether the server declares `logging` in its capabilities.

## Strategies

- `audit-erasure`
- `shadow-state`
- `boundary-leak`

## Judge contract

Confirm only when `facts.mutating_tools_without_log_call` is non-empty
AND the verdict's `evidence_path_used` references one of those tools.

## Remediation

Wire every mutating tool to a structured audit sink that records at
minimum: tool name, caller identity (or anonymous marker), parameters
hash, timestamp, and outcome. Declare `logging: true` in the server's
declared capabilities. Persist logs to durable storage, not stdout
alone.

## Traceability (machine-checked)

rule_id: shared-audit-trail-integrity
threat_refs:
- EU-AI-ACT-ART12
- ISO-27001-A.8.15
- OWASP-MCP09
strategies:
- audit-erasure
- shadow-state
- boundary-leak
