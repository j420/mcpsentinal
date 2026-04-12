# Rule Charter: cross-framework-kill-chain

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP01, OWASP ASI06, CoSAI T5, MAESTRO L3, EU AI Act Art.15, MITRE ATLAS AML.T0057

## Threat model

Real-world MCP attacks are rarely single-rule failures. The lethal
trifecta from F1, the sampling-amplification loop from `sampling-
capability-safety`, and the secret-exfiltration cross-product from
`secret-exfiltration-channels` are all *individual* structural
conditions. When they co-occur on the same server, they compose into
a kill chain: inject → amplify → exfiltrate, in under a minute.

This rule exists to express that composition explicitly. It does NOT
invent new signal — it reads the capability graph and flags the three
stages if they coexist:

- **Stage 1 — injection surface**: any tool carrying
  `ingests-untrusted` OR `receives-network`.
- **Stage 2 — amplifier**: any tool carrying `executes-code` or a
  server that declares `sampling`.
- **Stage 3 — egress**: any tool carrying `sends-network` with no
  consent marker, OR `manages-credentials` + `sends-network`.

When all three stages match distinct tools (or a declared capability +
tools), the rule emits `attack_chain_links` pointing to the companion
rules whose bundles compose the same chain. Reporters use those links
to render a kill-chain narrative.

## Real-world references

- **F1-MCP-Sentinel** — Lethal Trifecta analyzer rule. This rule is the
  compliance-framework counterpart.
- **arXiv-2601.17549** — sampling-amplified prompt injection (23-41%
  amplification). Stage 2 anchor.
- **OWASP-MCP01** — Prompt Injection.
- **OWASP-ASI06** — Memory & Context Poisoning.
- **MITRE-AML.T0057** — LLM Data Leakage. The impact stage.
- **Invariant-2026-CHAIN** — documented cross-framework kill-chain:
  web ingestion tool → sampling → slack send in a single MCP config,
  driving $6k exfiltration in 40 minutes.

## Lethal edge cases

1. **Web scraper + planner with sampling + Slack sender** — classic
   three-stage chain, single server.
2. **Email reader + executes-code + DNS egress** — Stage 3 bypasses
   HTTP filters via DNS exfiltration (G7-class).
3. **File reader + sampling + upload_file** — data-at-rest exfiltration
   via sampling-amplified summarization.

## Evidence the rule must gather

- Full capability graph via `graphFor`.
- `context.declared_capabilities?.sampling`.
- Cross-product match across the three stages.
- `attackChainLinks()` hook populates links to the companion rules.

## Strategies (for runtime test generation)

- `cross-tool-flow`
- `credential-laundering`
- `trust-inversion`

## Judge contract

A "fail" verdict is confirmed only if `facts.kill_chain_matched` is
true AND `facts.stage_tools` has non-empty arrays for every stage AND
the LLM's `evidence_path_used` references one of the stage tool names
or the literal `kill_chain`.

## Remediation

Break at least one stage of the chain. Most direct fixes: (a) move the
ingestion tool to a separate MCP server with no network egress, (b)
disable the sampling capability or add `inferenceQuota` / consent gate,
(c) add a consent marker to every network-sender tool. Fixing any one
stage breaks the chain.

## Traceability (machine-checked)

rule_id: shared-cross-framework-kill-chain
threat_refs:
- F1-MCP-Sentinel
- arXiv-2601.17549
- OWASP-MCP01
- OWASP-ASI06
- MITRE-AML.T0057
- Invariant-2026-CHAIN
strategies:
- cross-tool-flow
- credential-laundering
- trust-inversion
