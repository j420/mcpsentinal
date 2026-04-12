# Rule Charter: eu-ai-act-art13-transparency

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** medium
**Frameworks satisfied:** EU AI Act Art.13 — Transparency & Information to Users

## Threat model

EU AI Act Article 13 requires high-risk AI systems to be "designed and
developed in such a way to ensure that their operation is sufficiently
transparent to enable deployers to interpret a system's output and use
it appropriately". For an MCP server, the two structurally-checkable
transparency artifacts are:

1. **`initialize_metadata.server_version`** — deployers cannot
   reproduce or audit behaviour without a pinned version string.
2. **`initialize_metadata.server_instructions`** — this is the
   spec-sanctioned field where the server MUST explain its purpose,
   destructive capabilities, and human-oversight expectations. An
   empty or missing instructions field fails Art.13 transparency by
   construction.

An additional structural check: the declared-capabilities object must
match the observed surface (we do not re-implement
capability-declaration-honesty here; we just note its absence as an
Art.13 assist when present).

## Real-world references

- **EU-AI-Act-Art13-1** — transparency baseline.
- **EU-AI-Act-Art13-2** — mandatory information to deployers.
- **ISO-42001-A81** — ISO AI management system transparency clause.

## Lethal edge cases

1. **Missing server_version** — replay impossible.
2. **Empty instructions** — deployers cannot interpret outputs.
3. **Instructions declared `null`** — a silent-by-spec violation.

## Evidence the rule must gather

- `context.initialize_metadata?.server_version`.
- `context.initialize_metadata?.server_instructions`.
- Boolean flags for presence/absence of each.

## Strategies (for runtime test generation)

- `shadow-state`
- `trust-inversion`
- `audit-erasure`

## Judge contract

A "fail" verdict is confirmed only if `facts.art13_failures` is
non-empty AND the LLM's `evidence_path_used` references one of the
listed failure ids.

## Remediation

Populate `server_version` with a semver string, populate
`server_instructions` with a plain-language operator summary including
destructive capabilities and human-oversight requirements, and keep
both in sync with release notes.

## Traceability (machine-checked)

rule_id: eu-ai-act-art13-transparency
threat_refs:
- EU-AI-Act-Art13-1
- EU-AI-Act-Art13-2
- ISO-42001-A81
strategies:
- shadow-state
- trust-inversion
- audit-erasure
