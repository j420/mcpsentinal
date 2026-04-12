# Rule Charter: human-oversight-presence

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** EU AI Act Art.14, OWASP ASI09, CoSAI T2, MAESTRO L6

## Threat model

A high-risk MCP server exposes destructive operations (file deletion,
process termination, network mutation, payment, code execution) without a
structural confirmation gate that a human operator can use to intervene
*during* the operation. The agent can be socially engineered or context-poisoned
into invoking these tools, and there is no human checkpoint to stop it.

This is the central requirement of EU AI Act Article 14 and the
ASI09/T2/L6 controls. The lethal pattern is structural absence: the
server author assumed the AI client would handle confirmation, the AI
client assumed the server would, and nobody owns the gate.

## Real-world references

- **EU AI Act Art.14(4)** — natural persons must be able to "decide, in any
  particular situation, not to use the high-risk AI system or otherwise
  disregard, override or reverse the output."
- **Embrace The Red (2024)** — Claude Desktop forced into destructive
  filesystem operations via indirect prompt injection because no
  confirmation gate existed.
- **CVE-2025-53109 / 53110** (Anthropic filesystem MCP) — root-boundary
  bypass exposed because deletes were auto-approved.
- **Invariant Labs (2025)** — 84.2% tool poisoning success rate when the
  AI client auto-approves after consent fatigue.

## Lethal edge cases

1. **Annotation drift** — `readOnlyHint: true` paired with destructive
   parameter names (`delete`, `drop`, `overwrite`, `rmdir`, `truncate`).
2. **Pre-approval inheritance** — tool description references
   "permissions you already granted" or "same access as <other tool>".
3. **Batched destruction** — single tool accepts an array of targets so
   one approval destroys N resources.
4. **Auto-approve patterns in source** — code paths that explicitly bypass
   confirmation flows (`auto_confirm=True`, `skip_confirmation`,
   `--yes`, `--force`).
5. **Confirmation gate present but unreachable** — code declares a
   confirmation function but no destructive sink calls it (dead code).

## Evidence the rule must gather

- Per-tool destructive capability classification (capability graph).
- Per-tool annotation set.
- AST hits for confirmation-gate functions in the source.
- AST hits for destructive sinks (file delete, process kill, network
  mutation, eval, exec).
- For each destructive sink: does an enforced ordering relationship
  with a confirmation gate exist on the same control-flow path?

## Strategies (for runtime test generation)

- `consent-bypass`
- `human-oversight-bypass`
- `privilege-chain`

## Judge contract

The LLM verdict is confirmed only if the bundle's
`facts.destructive_sinks_without_gate` array is non-empty AND the
verdict's `evidence_path_used` references one of those sinks. Any
other "fail" verdict is rejected as a hallucination.

## Remediation

Wrap every destructive sink with an explicit confirmation gate that
either (a) requires a synchronous human approval, or (b) emits a
structured "pending" response and waits for the AI client's
human-oversight callback. Document the gate in the tool description
with `destructiveHint: true` and `requiresConfirmation: true`.

## Traceability (machine-checked)

rule_id: shared-human-oversight-presence
threat_refs:
- EU-AI-ACT-ART14
- EMBRACE-THE-RED-2024
- CVE-2025-53109
- INVARIANT-LABS-2025
strategies:
- consent-bypass
- human-oversight-bypass
- privilege-chain
