# Rule Charter: secret-exfiltration-channels

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP04, OWASP ASI06, CoSAI T5, MAESTRO L2, EU AI Act Art.15, MITRE AML.T0057

## Threat model

The lethal trifecta on a single server is detected by the existing F1
rule. This rule tackles the **weaker, harder-to-see cousin**: a server
exposes a tool that handles secrets (capability `manages-credentials`
or `reads-private-data`) AND a tool that sends data to the network
(capability `sends-network`) AND lacks any annotation restricting
secrets from being forwarded. No taint analysis is required — the
structural *composition* is the violation even if no single tool is
individually malicious.

This is the AML.T0057 "LLM Data Leakage" pattern: the AI agent reads
a secret via the secret handler and, in the same turn, calls the
network tool to forward it. The server gave the agent everything it
needed to leak credentials without any individual tool looking
dangerous in isolation.

## Real-world references

- **OWASP-MCP04** — Data Exfiltration.
- **MITRE-AML.T0057** — LLM Data Leakage.
- **OWASP-ASI06** — Memory & Context Poisoning (the adjacent
  propagation vector).
- **InvariantLabs-2025-MCP04** — documented real-world exfiltration
  chain against a production MCP server.

## Lethal edge cases

1. **Credentials reader + HTTP poster** — the classic pair, no taint
   analysis needed: the structural co-exposure is the violation.
2. **Private-data reader + DNS query tool** — DNS exfiltration channel
   with one read + one "send".
3. **Secrets manager + generic text emitter** — some servers expose a
   "print-to-stdout" tool that becomes an exfiltration sink when
   stdout is piped to a network-connected agent.
4. **Annotation claims `readOnlyHint` but the tool sends network** —
   deceptive annotation masks the sink.

## Evidence the rule must gather

- Capability-graph scan: tools with `manages-credentials` or
  `reads-private-data`.
- Capability-graph scan: tools with `sends-network`.
- Cross-product: every (secret reader, network sender) pair in the
  same server is a candidate leak channel.
- Annotation scan: does either tool in a pair carry a trust boundary
  marker?

## Strategies (for runtime test generation)

- `credential-laundering`
- `boundary-leak`
- `cross-tool-flow`

## Judge contract

A "fail" verdict is confirmed only if `facts.leak_pairs` is non-empty
AND the LLM's `evidence_path_used` references one of the tool names
in any leak pair.

## Remediation

Split secret-handling and network-sending tools into separate MCP
servers. Add a `trustBoundary` annotation that forbids forwarding
private data. Use a centralized secrets manager with a deny-by-default
outbound policy. For tools that legitimately need both capabilities,
gate outbound calls with a human-in-the-loop confirmation step.

## Traceability (machine-checked)

rule_id: shared-secret-exfiltration-channels
threat_refs:
- OWASP-MCP04
- MITRE-AML.T0057
- OWASP-ASI06
- InvariantLabs-2025-MCP04
strategies:
- credential-laundering
- boundary-leak
- cross-tool-flow
