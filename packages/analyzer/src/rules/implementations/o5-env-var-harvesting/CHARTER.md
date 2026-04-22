---
rule_id: O5
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MITRE-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. Environment variables
      in MCP server processes commonly hold the user's cloud
      credentials (AWS/GCP/Azure keys), third-party API tokens,
      database connection strings, and GitHub PATs. A bulk read
      ("dump every env var") exports the user's entire credential
      inventory in one call.
  - kind: spec
    id: CWE-200
    url: https://cwe.mitre.org/data/definitions/200.html
    summary: >
      CWE-200 — Exposure of Sensitive Information to an Unauthorized
      Actor. Bulk env-var enumeration is the canonical embodiment
      of this weakness: instead of reading one named variable the
      code needs, it reads all of them and the caller filters
      downstream — but the caller is the attacker.
  - kind: spec
    id: OWASP-MCP04
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. Environment
      harvesting is the highest-volume single call an MCP server
      can make against user secrets; the cost-to-value ratio for the
      attacker is extreme.

lethal_edge_cases:
  - >
    Node bulk read — `Object.keys(process.env)`,
    `Object.entries(process.env)`, `Object.values(process.env)`,
    `JSON.stringify(process.env)`, `{ ...process.env }` spread. A
    legitimate server reads one or two named variables; bulk reads
    are surveillance.
  - >
    Python bulk read — `os.environ.items()`, `os.environ.keys()`,
    `os.environ.values()`, `os.environ.copy()`, `dict(os.environ)`.
    Same pattern; cross-runtime coverage is required.
  - >
    For-each iteration without filter — `for (const k of
    Object.keys(process.env))`, `for k in os.environ:`, `.forEach`,
    `.map` on the entire env set without a safelist identifier in
    the loop body. Masquerades as loop code but extracts everything.
  - >
    Targeted read of one variable is NOT O5 — `process.env.FOO`,
    `os.environ["FOO"]`, `os.getenv("FOO")`. These read a single
    named variable and are legitimate. The gather step matches on
    the *bulk-access* expression shape, not the existence of any
    `process.env` reference.

edge_case_strategies:
  - ast-bulk-read-shape-match                  # Object.keys / entries / values on process.env or os.environ
  - shared-env-var-vocabulary                  # DATA_EXFIL_SINKS env-var kind
  - spread-destructure-detection               # `{ ...process.env }` treated as bulk
  - test-file-structural-skip

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - env_var_bulk_read_observed
    - no_allowlist_filter_in_scope
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP client runtimes scrub or box server access to `process.env`
    / `os.environ` through a per-variable allowlist capability, OR
    the MCP spec declares environment-variable access as a
    user-approved capability that the client enforces. Neither
    exists as of 2026-04.
---

# O5 — Environment Variable Harvesting

## Threat Model

Environment variables in MCP server processes are an attacker
bonanza: cloud credentials, API tokens, database URLs. The
legitimate server reads one variable — the one it needs. A
malicious server reads all of them with `Object.keys(process.env)`
or `os.environ.items()`, encodes the payload, and forwards via any
subsequent tool response or network call.

## Detection Strategy — AST Shape Match

Regex on the string `process.env` matches every legitimate access.
O5 cares only about BULK expression shapes:

- `Object.keys/entries/values/fromEntries(process.env)`
- `JSON.stringify(process.env)`
- Object spread `{ ...process.env }`
- Python `os.environ.items/keys/values/copy`, `dict(os.environ)`

These patterns are matched structurally in the AST — the receiver
of the call must be `process.env` (or `os.environ`) and the method
must be a known bulk accessor. A single `process.env.FOO` never
fires. Zero regex literals.

## Confidence Cap

**0.85** — very strong structural signal. One legitimate edge-case
exists: test harnesses that dump env for debugging. The
test-file structural skip handles that; the confidence cap holds
headroom for legitimate debug code that does not live in a
detectable test file.
