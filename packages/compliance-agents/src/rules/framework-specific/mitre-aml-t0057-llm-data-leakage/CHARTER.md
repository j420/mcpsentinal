# Rule Charter: mitre-aml-t0057-llm-data-leakage

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** MITRE ATLAS AML.T0057 — LLM Data Leakage

## Threat model

MITRE ATLAS technique AML.T0057 covers data leakage through an LLM —
the "private data → tool output" flow where a server reads private
data (filesystem, credential store, user data) and returns it in a
tool response that the LLM then processes and can re-emit.

The structural anchor is a capability-graph node that carries BOTH
`reads-private-data` AND has no `writes-data` sibling that contains
a redaction marker — i.e. the private data flows into tool output
without transformation. Combined with a network-sender tool (same
server), this forms a T0057 realization.

The compliance finding is independent of F1 (which covers the
broader trifecta) — this rule specifically frames the finding in
MITRE ATLAS taxonomy for reports consumed by threat-model-aware
auditors.

## Real-world references

- **MITRE-AML.T0057** — canonical LLM Data Leakage technique.
- **OWASP-MCP04** — Data Exfiltration.
- **CVE-2025-LEAK** — documented MCP server that returned
  `/etc/shadow` via a tool response after an indirect prompt
  injection.

## Lethal edge cases

1. **`read_file` on `/etc/shadow`** — classic data-at-rest leak.
2. **Credential vault reader returning secrets in tool response** —
   `manages-credentials` with no redaction path.
3. **User-data reader + HTTP egress** — end-to-end T0057 chain.

## Evidence the rule must gather

- Capability graph nodes with `reads-private-data` or
  `manages-credentials`.
- Intersecting set with `sends-network`.
- Returns the pair list as `leakage_pairs`.

## Strategies (for runtime test generation)

- `credential-laundering`
- `cross-tool-flow`
- `boundary-leak`

## Judge contract

A "fail" verdict is confirmed only if `facts.leakage_pairs` is
non-empty AND the LLM's `evidence_path_used` references one of the
leakage pair tool names or the literal `llm_data_leakage`.

## Remediation

Redact private data at the source tool before it enters tool
responses. Add a structural redaction layer and ensure no network
sender can observe raw private-data responses. Split readers and
senders into separate MCP servers with no shared memory.

## Traceability (machine-checked)

rule_id: mitre-aml-t0057-llm-data-leakage
threat_refs:
- MITRE-AML.T0057
- OWASP-MCP04
- CVE-2025-LEAK
strategies:
- credential-laundering
- cross-tool-flow
- boundary-leak
