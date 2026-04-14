# Rule Charter: eu-ai-act-art12-record-keeping

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** high
**Frameworks satisfied:** EU AI Act Art.12 (exclusively)

## Threat model

EU AI Act Article 12 requires high-risk AI systems to "automatically
record events ('logs') over the duration of the system's lifetime to
ensure traceability." For an MCP server in a high-risk pipeline,
"lifetime traceability" means: every tool invocation must produce a
record that survives container restart, identifies the caller (or an
anonymous-but-stable marker), and can be replayed by an auditor.

The lethal pattern this rule detects is *Article 12-specific*: even
when generic logging exists (covered by `audit-trail-integrity`), the
records may fail Art.12 because they:
- Lack a stable timeline (no monotonic timestamp).
- Lack the ability to reconstruct the prompt/parameter set.
- Are stored only in ephemeral memory or stdout.
- Are missing the "system version" / "rules version" tag required for
  cross-time replay.

## Real-world references

- **EU AI Act Art.12(1)** — automatic recording mandate.
- **EU AI Act Art.12(2)** — traceability over lifetime requirement.
- **EU AI Act Art.12(3)** — high-risk system specific obligations.

## Lethal edge cases

1. **Logs without stable timestamps** — only relative offsets, no UTC.
2. **Logs without server version pin** — replay against the wrong
   ruleset is silent and undetectable.
3. **Stdout-only logs** — survive nothing.
4. **Logs that drop the parameter set** to "save space" — replay is
   impossible.
5. **Logging that is `console.log`-shaped** rather than structured.

## Evidence the rule must gather

- Whether the source files map binds a structured logging library.
- Whether `connection_metadata` indicates a persistent backend exists.
- Whether the server declares its version via `initialize_metadata`.

## Strategies

- `audit-erasure`
- `shadow-state`
- `boundary-leak`

## Judge contract

Confirm only when `facts.art12_failures` is non-empty AND the verdict
references one of the listed failure ids.

## Remediation

Use a structured logger (pino/winston/bunyan), persist to durable
storage with monotonic UTC timestamps, include the parameter hash and
server version on every record, and emit a daily integrity hash for
the log batch.

## Traceability (machine-checked)

rule_id: eu-ai-act-art12-record-keeping
threat_refs:
- EU-AI-ACT-ART12-1
- EU-AI-ACT-ART12-2
strategies:
- audit-erasure
- shadow-state
- boundary-leak
