# Rule Charter: prompt-injection-resilience

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP01, OWASP ASI01, CoSAI T4, MAESTRO L3, MITRE AML.T0054

## Threat model

An MCP server ingests untrusted content (web pages, emails, issue trackers,
file contents) and exposes it to the AI client without an isolation
boundary. An attacker who controls any one of those untrusted sources can
inject instructions that the AI client will obey because the server made
no structural attempt to mark, sandbox, or sanitize the content as
adversarial.

The lethal pattern is the *combination* of:
1. an ingestion sink (a tool that pulls untrusted external content), and
2. the absence of any "untrusted content boundary" in the tool's
   description, parameter schema, or output schema.

## Real-world references

- **Embrace The Red (2024)** — indirect prompt injection demonstrations
  against Claude via web-scraping MCP servers.
- **Invariant Labs (2025)** — MCP indirect injection paper.
- **AML.T0054.001** — MITRE ATLAS technique for indirect prompt injection.

## Lethal edge cases

1. **Read-then-summarize tools** that surface raw remote content as
   tool output without delimiters, schemas, or content-type tagging.
2. **Tools whose description claims a "trust" property** ("returns
   sanitized HTML") that the schema does not enforce.
3. **Outputs typed as `string`** containing both control instructions
   and untrusted text, with no separation.
4. **Tools that claim to "summarize" but actually pass through** the
   underlying content verbatim.
5. **Multi-step pipelines** where untrusted content flows into a second
   tool's input parameter without re-scrutiny.

## Evidence the rule must gather

- All tools whose capability graph node includes `ingests-untrusted`.
- For each, the presence (or absence) of structural boundary signals:
  declared output schema, content-type discriminators, sanitizer
  annotations.
- Cross-tool flows where ingested content reaches a tool that triggers
  downstream actions.

## Strategies

- `boundary-leak`
- `cross-tool-flow`
- `trust-inversion`

## Judge contract

The LLM verdict is confirmed only when
`facts.unbounded_ingestion_sinks` is non-empty AND the verdict's
`evidence_path_used` references one of those tools.

## Remediation

For every tool that ingests untrusted content, declare an output schema
with a `content_type` discriminator separating `model_message` from
`untrusted_content`. Document the boundary in the tool description and
ensure no downstream tool blindly forwards `untrusted_content` without
re-tagging.

## Traceability (machine-checked)

rule_id: shared-prompt-injection-resilience
threat_refs:
- EMBRACE-THE-RED-INDIRECT
- INVARIANT-LABS-PI-2025
- MITRE-ATLAS-T0054-001
strategies:
- boundary-leak
- cross-tool-flow
- trust-inversion
