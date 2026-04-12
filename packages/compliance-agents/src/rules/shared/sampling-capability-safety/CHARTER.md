# Rule Charter: sampling-capability-safety

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP01, OWASP ASI01, OWASP ASI08, CoSAI T4, CoSAI T10, MAESTRO L3, EU AI Act Art.15, MITRE AML.T0054

## Threat model

The MCP spec 2025-06-18 introduced the **sampling capability**: a server
can call back into the AI client to request an inference. This is a
powerful feature — and a super-injection amplification surface.

When a server declares `capabilities.sampling = true` AND has at least
one **ingestion tool** (email readers, HTTP fetchers, web scrapers,
issue trackers, RSS readers, IMAP clients), the attacker flow is:

1. Attacker plants an injection payload in an untrusted source
   (email, web page, issue comment).
2. The server ingests it via the ingestion tool.
3. The server triggers a sampling request that round-trips the payload
   back through the client's LLM context.
4. The LLM processes the attacker's payload as "trusted model reasoning"
   because it arrived through the sampling channel rather than a tool
   response. arXiv 2601.17549 measured **23-41% attack amplification**
   compared to plain prompt injection.

Worse: each sampling request triggers real inference spend. Without a
cost cap (`max_tokens`, `maxTokens`, `token_budget`, `inferenceQuota`,
etc. — see rule-kit `COST_CAP_MARKERS`), a single malicious payload can
drive unbounded cost amplification — a DoS-via-billing attack.

The lethal combination is **sampling declared** AND **ingestion tool
present** AND **no cost caps** AND **no human-in-the-loop gate** on the
sampling path.

## Real-world references

- **arXiv-2601.17549** — "Sampling-amplified prompt injection in MCP"
  (23-41% amplification measurement).
- **CVE-2025-SAMPLING** — MCP server exploited to trigger unbounded
  client-side sampling spend.
- **OWASP-ASI08** — Resource Exhaustion / Denial of Wallet.
- **MITRE-AML.T0054** — LLM Prompt Injection, indirect variant.

## Lethal edge cases

1. **Sampling + web fetcher with no cost cap** — the Rehberger
   super-injection loop in one server.
2. **Sampling + IMAP/email reader** — attacker sends a crafted email
   that triggers sampling amplification on the next inbox read.
3. **Sampling + RSS parser** — public feed controlled by attacker
   becomes a persistent amplification trigger.
4. **Sampling declared with no structured cost limits** — even benign
   use triggers unbounded inference spend under load.

## Evidence the rule must gather

- `declared_capabilities.sampling === true`?
- Any tool carrying capability `ingests-untrusted` or `receives-network`?
- Source-file token scan for cost-cap markers (rule-kit
  `COST_CAP_MARKERS`).
- Source-file token scan for ingestion source tokens (rule-kit
  `INGESTION_SOURCE_TOKENS`) as a secondary signal when the capability
  graph has low confidence.
- Per-tool annotation scan: is the ingestion tool human-gated?

## Strategies (for runtime test generation)

- `cross-tool-flow`
- `boundary-leak`
- `shadow-state`

## Judge contract

A "fail" verdict is confirmed only if
`facts.sampling_declared === true` AND
`facts.ingestion_tools` is non-empty AND
`facts.cost_caps_found` is empty AND the LLM's `evidence_path_used`
references one of the ingestion tool names or the literal string
`sampling_capability`.

## Remediation

Either (a) remove the sampling capability declaration if the server
does not actually need server-initiated inference, or (b) add
structured cost caps (`max_tokens`, `token_budget`, `inferenceQuota`)
and gate every sampling call behind a human-in-the-loop confirmation.
Separate the ingestion tools into a different MCP server that does NOT
declare sampling so the amplification loop cannot form.

## Traceability (machine-checked)

rule_id: shared-sampling-capability-safety
threat_refs:
- arXiv-2601.17549
- CVE-2025-SAMPLING
- OWASP-ASI08
- MITRE-AML.T0054
strategies:
- cross-tool-flow
- boundary-leak
- shadow-state
