# Rule Charter: destructive-operation-gating

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP06, OWASP ASI09, CoSAI T2, CoSAI T9, MAESTRO L6, EU AI Act Art.14, MITRE AML.T0059

## Threat model

A destructive tool exists — one that can delete, overwrite, drop,
truncate, send an irreversible email, execute a shell command, push
a commit, or otherwise cause state that cannot be rolled back. The MCP
spec provides the `destructiveHint: true` annotation precisely for
this class of tool so that clients can gate it behind explicit user
confirmation.

The failure mode is structural: the capability graph identifies the
tool as destructive, but the tool carries `destructiveHint: false`
(or omits the annotation entirely) AND carries no consent marker.
The result: clients auto-approve the tool, the agent invokes it
without a human-in-the-loop, and the destructive operation executes
with no recovery path.

EU AI Act Art.14 explicitly requires that operators of high-risk AI
systems maintain "effective human oversight" of high-impact decisions.
Destructive tools are the canonical high-impact decision, and the
rule enforces the structural pre-condition for Art.14 compliance.

## Real-world references

- **CVE-2025-53109** / **CVE-2025-53110** — Anthropic filesystem
  server root boundary bypass allowed destructive ops beyond the
  intended scope.
- **OWASP-ASI09** — Human Oversight.
- **EU-AI-Act-Art14** — regulatory requirement for human oversight.
- **Invariant-2025-DESTRUCT** — documented incident where a
  destructive tool lacked consent gating and caused irreversible
  data loss on a production agentic workflow.

## Lethal edge cases

1. **Destructive tool with `readOnlyHint: true`** — the annotation
   lies about the tool's capability; F1 covers the trifecta case,
   but this rule fires on the simpler single-tool deception.
2. **Destructive tool with no annotations at all** — the default
   "open world" where the client has no structural signal.
3. **Destructive capability via parameter defaults** — tool is
   harmless unless `recursive=true` and `force=true`, both default
   to `true`.
4. **Tool named innocuously** (`sync_down`, `cleanup`, `rotate`)
   that performs irreversible deletion.

## Evidence the rule must gather

- Capability-graph scan: tools with `destructive` or `executes-code`.
- Per-tool annotation scan: is `destructiveHint` present and `true`?
- Per-tool annotation scan: is any CONSENT_MARKER_KEYS entry present?
- Cross-check: which destructive tools have neither
  `destructiveHint=true` nor any consent marker.

## Strategies (for runtime test generation)

- `human-oversight-bypass`
- `consent-bypass`
- `privilege-chain`

## Judge contract

A "fail" verdict is confirmed only if `facts.ungated_destructive_tools`
is non-empty AND the LLM's `evidence_path_used` references one of
those tool names.

## Remediation

Add `destructiveHint: true` AND a consent marker
(`requiresConfirmation: true` or `humanInTheLoop: true`) to every
destructive, code-executing, or irreversible tool. Require the client
to prompt the user before invocation. Never ship a destructive tool
with `readOnlyHint: true` or without any annotation.

## Traceability (machine-checked)

rule_id: shared-destructive-operation-gating
threat_refs:
- CVE-2025-53109
- CVE-2025-53110
- OWASP-ASI09
- EU-AI-Act-Art14
- Invariant-2025-DESTRUCT
strategies:
- human-oversight-bypass
- consent-bypass
- privilege-chain
