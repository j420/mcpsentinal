# Rule Charter: consent-fatigue-resistance

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP06, OWASP ASI09, CoSAI T2, CoSAI T9, MAESTRO L6, EU AI Act Art.14

## Threat model

An MCP server ships many benign tools (file readers, formatters, status
probes) alongside a small number of dangerous ones (destructive file
operations, shell execution, secret managers). When the user approves the
server in a client like Claude Desktop or Cursor, they must approve all
tools at once — or, over a session, approve them in rapid succession.
After approving ten safe tools, humans auto-approve the eleventh without
scrutiny. Invariant Labs documented an **84.2% success rate** for tool
poisoning under auto-approve flows (2025).

The structural failure is **imbalance with no structural gate**: if a
server has ≥10 benign tools AND ≥1 destructive tool AND no annotation
(`requiresConfirmation`, `humanInTheLoop`, `needsApproval`,
`confirmationRequired`, `userMustApprove`) on the destructive tool,
consent fatigue is a deterministic outcome, not a user error.

This is distinct from human-oversight-presence (which checks whether
*any* oversight gate exists). Consent fatigue is about the **ratio**
and the **distribution** of risk: a few hidden dangerous tools among
many safe ones exploit approval exhaustion even when the dangerous tools
individually carry oversight annotations.

## Real-world references

- **Invariant-Labs-2025** — "Consent fatigue in agentic MCP clients"
  (84.2% attack success under auto-approve).
- **OWASP-ASI09** — Human Oversight is the ASI09 control.
- **OWASP-MCP06** — Excessive Permissions control explicitly names
  approval-overhead anti-patterns.
- **CVE-2025-FATIGUE** — reported MCP client auto-approve exploit
  against a file management server.

## Lethal edge cases

1. **One dangerous tool hidden among twenty benign** — exact Invariant
   Labs reproduction.
2. **Dangerous tool has destructive capability AND no consent marker**
   — user has no structural gate.
3. **Benign/destructive ratio ≥10 AND server declares no per-tool
   annotations at all** — any auto-approve session compromises the
   dangerous tool trivially.
4. **Destructive tool last in alphabetical order** — clients that
   render approval lists alphabetically surface it after the user has
   already approved a large batch.

## Evidence the rule must gather

- Capability-graph classification: which tools are `destructive` /
  `executes-code` / `manages-credentials`?
- Capability-graph classification: which tools are benign readers
  (`reads-public-data`, `reads-private-data` with no write/destructive)?
- Per-tool annotation scan: does each destructive tool carry a consent
  marker from the centralized marker catalog?
- Ratio check: `benign_count >= 10 AND dangerous_count >= 1` is the
  structural trigger; unannotated dangerous tools inside that ratio
  are the deterministic violation.

## Strategies (for runtime test generation)

- `consent-bypass`
- `human-oversight-bypass`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if `facts.unannotated_dangerous_tools`
is non-empty AND the LLM's `evidence_path_used` references one of those
tool names.

## Remediation

Add explicit consent annotations to every destructive, code-executing,
or credential-handling tool:
`{ requiresConfirmation: true, humanInTheLoop: true }`. Prefer grouping
dangerous tools into a separate MCP server the user must approve with
a distinct, informed consent step. Never hide a destructive tool in a
large batch of benign ones without an annotation.

## Traceability (machine-checked)

rule_id: shared-consent-fatigue-resistance
threat_refs:
- Invariant-Labs-2025
- OWASP-ASI09
- OWASP-MCP06
- CVE-2025-FATIGUE
strategies:
- consent-bypass
- human-oversight-bypass
- trust-inversion
