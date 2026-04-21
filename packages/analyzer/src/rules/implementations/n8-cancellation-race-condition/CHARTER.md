---
rule_id: N8
name: Cancellation Race Condition
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: protocol-transport
threat_refs:
  - kind: spec
    id: MCP-2025-03-26-cancellation
    url: https://modelcontextprotocol.io/specification/2025-03-26/basic/utilities/cancellation
    summary: "MCP spec 2025-03-26 §5.3 defines notifications/cancelled as advisory — 'the operation may have already completed'. Servers that process cancellation without checking committed state leave partial mutations in place or roll back already-delivered results."
  - kind: paper
    id: CWE-367-TOCTOU
    url: https://cwe.mitre.org/data/definitions/367.html
    summary: "CWE-367 Time-Of-Check Time-Of-Use race. MCP cancellation reproduces the class when the cancel handler reads 'is the operation still running' and acts on that read without an atomic guard."
  - kind: incident
    id: AbortController-non-atomic
    url: https://nodejs.org/api/globals.html#class-abortcontroller
    summary: "AbortController provides a signal but no atomic commit/rollback; using it to gate mutations without a transaction leaves partial state. Node's own docs caution that abort is cooperative and mutation sites must coordinate."
lethal_edge_cases:
  - id: cancel-after-commit
    description: "Cancel handler invokes rollback() or delete() on data the operation has already flushed to durable storage. The subsequent completion callback still runs, observing the rollback and reporting success."
  - id: abortsignal-without-transaction
    description: "Code uses AbortSignal on an async write path but never wraps the mutation in a transaction — the signal aborts the JS promise chain, not the underlying side effect."
  - id: cleanup-in-catch-without-state-check
    description: "`try { await write() } catch (AbortError) { await deletePartial() }` — the catch runs even if write() already committed before the abort was raised."
  - id: toctou-on-committed-flag
    description: "Handler reads `if (!op.committed) rollback()` but doesn't hold a lock — a concurrent completion can flip committed between the check and the rollback."
edge_case_strategies:
  - cancel_handler_without_commit_check
  - abortsignal_guarding_mutation_without_transaction
  - catch_abort_error_then_delete_or_rollback
evidence_contract:
  minimum_chain:
    - source
    - propagation
    - sink
    - mitigation
    - impact
  required_factors:
    - cancellation_without_atomic_guard
  location_kinds:
    - source_code_line
obsolescence:
  retire_when: "MCP spec mandates that servers MUST wrap cancellable mutations in a transaction OR explicitly document the non-atomic contract, AND mainstream MCP SDKs ship helpers that encapsulate this pattern."
---

# N8 — Cancellation Race Condition

## Threat narrative

MCP's `notifications/cancelled` is advisory. The spec (2025-03-26 §5.3) says explicitly that the cancelled operation "may have already completed"; the server must tolerate receiving a cancel for work that is mid-flight, not-yet-started, or already-finished. The class of bugs the rule targets is the cancel handler that assumes "cancelled means not-yet-committed" and responds by deleting data, rolling back state, or emitting a "cancelled" response — without first checking that the mutation was in fact un-committed and without atomically locking against a concurrent completion.

The defect has two concrete shapes. First, an `AbortSignal`-guarded async write path where the abort aborts the JS promise chain but not the underlying side effect: the HTTP request was issued, the database INSERT ran, the file was written; only the `await` resolves with AbortError. Cleanup in the catch branch deletes the partial result without confirming the original write actually failed. Second, a cancel handler that reads a `committed` flag without holding a lock: a concurrent completion can flip the flag between the check and the action, yielding a TOCTOU race (CWE-367).

The rule detects these shapes by looking for:
- A cancellation-keyword construct: `AbortController`, `AbortSignal`, `onCancelled`, `handleCancel`, `notifications/cancelled`.
- A mutation call in the same scope: `.write`, `.insert`, `.update`, `.delete`, `fs.writeFile`, `db.execute`, `.run`, `.exec`.
- Absence of a transaction / atomic-commit wrapper: no `beginTransaction`, `transaction`, `commit`, `rollback`, `atomic`, `lock`, `mutex` vocabulary in the enclosing function.

## Evidence contract

1. **Source**: the cancel-handler registration (AbortController.signal.addEventListener, onCancelled, notifications/cancelled handler).
2. **Propagation**: the assignment or call path from the cancel signal to the mutation site.
3. **Sink**: the mutation call (write/insert/update/delete/rollback/etc.) the cancel handler touches.
4. **Mitigation**: absence of transaction / lock vocabulary in the enclosing function.
5. **Impact**: partial-state corruption (config-poisoning scope) with moderate exploitability.

## Lethal edge cases

- **cancel-after-commit**: cancel handler rolls back already-flushed data.
- **abortsignal-without-transaction**: AbortSignal on a write path; cleanup assumes the write failed.
- **cleanup-in-catch-without-state-check**: `catch (AbortError) { deletePartial(); }`.
- **toctou-on-committed-flag**: check-then-act on a committed flag without locking.

## Confidence ceiling

Cap at 0.80. The rule cannot verify transactional semantics from static text alone — some code uses database-level idempotent upserts that are safe without a transaction. 0.80 reflects this residual uncertainty.
