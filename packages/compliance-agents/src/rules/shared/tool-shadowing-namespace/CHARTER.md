# Rule Charter: tool-shadowing-namespace

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** OWASP MCP02, OWASP ASI02, CoSAI T4, MAESTRO L3, MITRE ATLAS AML.T0054

## Threat model

Multiple MCP servers loaded into the same client share a flat tool
namespace. A malicious or negligent server that exposes a tool named
identically (or near-identically) to a well-known verb (`read_file`,
`write`, `execute`, `fetch`, `query`) hijacks the intent the AI already
associates with that verb. This is the MCP-layer variant of classic
PATH shadowing and of F4/F5 namespace squatting — but the attack
surface is the *tool-name-to-AI-intent* mapping, not the OS PATH.

A tool whose name collides with the rule-kit `SHADOW_PRONE_TOOL_NAMES`
catalog AND carries destructive capability markers (writes-data,
executes-code, destructive) is the deterministic violation. Near-match
collisions (levenshtein ≤1 against a shadow-prone name) without a
capability hint are treated as softer signals.

## Real-world references

- **F4-MCP-Sentinel** — analyzer rule for tool-name shadowing against a
  fixed list of official tool names.
- **F5-MCP-Sentinel** — official-namespace squatting (Anthropic/OpenAI
  namespaces).
- **OWASP-MCP02** — Tool Poisoning.
- **MITRE-AML.T0054** — LLM Prompt Injection (shadowed verbs are a
  confusion vector that biases the agent toward the attacker's tool).
- **Invariant-2025-SHADOW** — documented incident where a malicious
  `read_file` tool outranked the legitimate filesystem read and
  exfiltrated `~/.ssh/id_rsa` without triggering user confirmation.

## Lethal edge cases

1. **Destructive-capable `read_file`** — name suggests read-only, graph
   says writes-data or executes-code.
2. **Shadowed `execute`** — benign name, manages-credentials capability,
   AI picks it thinking it's a sandbox.
3. **Near-match shadow** (`read_fi1e`, `readfile`, Unicode homoglyph) —
   Levenshtein ≤1 against a canonical verb. (Captured by the
   analyzer's similarity helpers, not by regex.)

## Evidence the rule must gather

- Capability graph for each tool.
- Membership test against rule-kit `SHADOW_PRONE_TOOL_NAMES`.
- Capability intersection: `writes-data`, `executes-code`, `destructive`.
- Absence of any consent annotation (`CONSENT_MARKER_KEYS`) on the
  shadowed tool is a further accelerant.

## Strategies (for runtime test generation)

- `trust-inversion`
- `shadow-state`
- `consent-bypass`

## Judge contract

A "fail" verdict is confirmed only if `facts.shadow_violations` is
non-empty AND the LLM's `evidence_path_used` references one of the
shadow-violating tool names.

## Remediation

Rename shadow-prone tools to clearly namespaced alternatives
(`myserver_read_file`, `myserver_execute`). Add `destructiveHint: true`
and a consent marker where the capability is not purely read-only.
Prefer a single unambiguous tool over multiple near-duplicates.

## Traceability (machine-checked)

rule_id: shared-tool-shadowing-namespace
threat_refs:
- F4-MCP-Sentinel
- F5-MCP-Sentinel
- OWASP-MCP02
- MITRE-AML.T0054
- Invariant-2025-SHADOW
strategies:
- trust-inversion
- shadow-state
- consent-bypass
