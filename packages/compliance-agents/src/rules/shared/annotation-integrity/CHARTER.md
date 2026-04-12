# Rule Charter: annotation-integrity

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP02, OWASP ASI02, CoSAI T4, MAESTRO L3, EU AI Act Art.13, MITRE AML.T0054

## Threat model

Beyond the destructive-operation-gating rule (which tackles the
`destructiveHint` case), there is a broader class of **annotation
lying**: tools whose declared `idempotentHint`, `openWorldHint`, or
`readOnlyHint` disagrees with the structural capability graph. MCP
clients rely on these annotations to decide when to batch calls, when
to retry, when to auto-approve, and when to restrict side effects.
A server that lies on any of them causes the client to make wrong
safety decisions.

- `idempotentHint: true` claimed on a tool that writes data → the
  client will retry on failure and create duplicate writes.
- `openWorldHint: false` claimed on a tool that calls external
  services → the client will treat the tool as closed-world and
  not log it for provenance tracking.
- `readOnlyHint: true` claimed on any writer → the client will
  auto-approve and skip confirmation.

This is the I1-style "Annotation Deception" pattern lifted to the
compliance layer with framework mappings instead of severity scores.
It complements, not duplicates, the existing analyzer I1 rule: the
compliance version produces an EvidenceBundle auditors can replay.

## Real-world references

- **I1-MCP-Sentinel** — the existing analyzer rule for annotation
  deception on `destructiveHint`, extended here to the full
  annotation surface.
- **Invariant-2025-IDEM** — documented case where `idempotentHint:
  true` on a non-idempotent tool caused duplicate production writes.
- **MCP-Spec-2025-03-26** — introduced `idempotentHint` and
  `openWorldHint` as first-class annotations.
- **OWASP-MCP02** — Tool Poisoning.

## Lethal edge cases

1. **idempotentHint: true on a writer** — client retries a destructive
   call and duplicates the side effect.
2. **openWorldHint: false on a tool that uses the network** — no
   provenance, no logging, external call happens invisibly.
3. **readOnlyHint: true on a tool with `writes-data` or `destructive`
   capability** — the most lethal annotation lie.
4. **All hints absent on a dangerous tool** — "default open" posture,
   the client has no signal at all.

## Evidence the rule must gather

- Capability-graph caps per tool.
- Annotation values for `destructiveHint`, `readOnlyHint`,
  `idempotentHint`, `openWorldHint`.
- Disagreement matrix: which annotation→capability pairs are
  structurally impossible?

## Strategies (for runtime test generation)

- `trust-inversion`
- `shadow-state`
- `consent-bypass`

## Judge contract

A "fail" verdict is confirmed only if `facts.lying_annotations` is
non-empty AND the LLM's `evidence_path_used` references one of the
listed tool names.

## Remediation

Never set `readOnlyHint: true` on a tool with any write/destructive
capability. Never set `idempotentHint: true` on a non-idempotent tool.
Never set `openWorldHint: false` on a tool that issues network calls.
When in doubt, omit the annotation so the client's default conservative
posture applies.

## Traceability (machine-checked)

rule_id: shared-annotation-integrity
threat_refs:
- I1-MCP-Sentinel
- Invariant-2025-IDEM
- MCP-Spec-2025-03-26
- OWASP-MCP02
strategies:
- trust-inversion
- shadow-state
- consent-bypass
