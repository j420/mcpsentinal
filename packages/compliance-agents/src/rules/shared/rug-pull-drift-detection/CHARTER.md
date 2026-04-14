# Rule Charter: rug-pull-drift-detection

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP02, OWASP ASI04, CoSAI T6, MAESTRO L4, EU AI Act Art.15

## Threat model

The classic rug-pull: a server establishes trust with a small, benign
tool surface, gets added to thousands of agent configs, then silently
introduces destructive tools or rewrites descriptions on a later
release. This is not hypothetical — analyzer rule G6 already catches
sudden changes; this compliance rule lifts the same signal into the
per-framework reports and covers a subtler variant (I14 rolling
capability drift): gradual, below-threshold accumulation over many
releases that never trips a single-scan alarm.

The rule is temporal — it overrides `gatherTemporalEvidence()` so the
orchestrator feeds it a window of prior bundles. The deterministic
anchor is a *delta*: the set of current dangerous-capability tools
minus the set from the oldest prior bundle in the window. A
non-empty delta where the new tools carry `destructive`,
`executes-code`, or `manages-credentials` is the violation.

## Real-world references

- **G6-MCP-Sentinel** — analyzer rule for sudden tool-count /
  description drift.
- **I14-MCP-Sentinel** — rolling capability drift (slow accumulation).
- **OWASP-MCP02** — Tool Poisoning (rug-pull is the temporal form).
- **CoSAI-T6** — supply-chain drift.
- **CVE-2025-RUGPULL** — documented incident: popular MCP server added
  `shell_exec` in a patch release after reaching 20k installs.

## Lethal edge cases

1. **Sudden addition of `shell_exec`** in a patch release.
2. **Benign `read_file` → destructive `read_file`** where the capability
   graph classification flips between scans.
3. **Rolling drift**: +1 dangerous tool per monthly release for six
   months — no individual release trips G6 but the cumulative delta
   is catastrophic.

## Evidence the rule must gather

- Current capability graph and dangerous-tool set.
- Temporal window from the orchestrator (`HistoricalBundleRef[]`).
- Oldest prior bundle in the window — used as the baseline for delta
  computation.
- Delta set: current dangerous tools minus baseline dangerous tools.

## Strategies (for runtime test generation)

- `config-drift`
- `supply-chain-pivot`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if `facts.new_dangerous_tools` is
non-empty AND `facts.history_window_size` >= 1 AND the LLM's
`evidence_path_used` references one of the new dangerous tool names
or the literal `capability_drift`.

## Remediation

Treat dangerous-capability additions as breaking changes. Publish a
CHANGELOG entry, bump the major version, and signal the change via a
declared-capability diff. Consumers should pin the MCP server version
and enforce a re-audit on capability-level diff.

## Traceability (machine-checked)

rule_id: shared-rug-pull-drift-detection
threat_refs:
- G6-MCP-Sentinel
- I14-MCP-Sentinel
- OWASP-MCP02
- CoSAI-T6
- CVE-2025-RUGPULL
strategies:
- config-drift
- supply-chain-pivot
- trust-inversion
