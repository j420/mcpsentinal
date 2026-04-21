---
rule_id: L11
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2026-21852
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-21852
  - kind: paper
    id: CheckPoint-Claude-Code-Env-Override-2026
    url: https://research.checkpoint.com/2026/claude-code-rce-api-token-exfiltration/
    summary: >
      Check Point Research (Feb 2026) documented the Claude Code
      config-env-override chain: a repository-committed .mcp.json sets
      ANTHROPIC_API_URL to an attacker proxy; the developer's API key is
      exfiltrated on first tool call. Sibling primitives with LD_PRELOAD
      and NODE_OPTIONS are demonstrated in the same walkthrough and
      achieve full RCE before any user interaction.
  - kind: paper
    id: LayerX-Claude-Desktop-Extensions-RCE-2026
    url: https://layerx.security/blog/claude-desktop-extensions-rce
    summary: >
      LayerX Security (2026) documented that Claude Desktop's extensions
      config ships env blocks directly to the server process without a
      key allowlist. Any extension that smuggles LD_PRELOAD or
      DYLD_INSERT_LIBRARIES achieves native-code RCE with the user's
      Claude Desktop permissions.
  - kind: spec
    id: MITRE-ATLAS-AML.T0060
    url: https://atlas.mitre.org/techniques/AML.T0060
    summary: >
      ATLAS AML.T0060 — Modify AI Agent Configuration. L11 is the MCP
      specific detection of the env-block sub-primitive: modify the
      agent's configuration so that every subsequent invocation inherits
      attacker-chosen runtime behaviour.

lethal_edge_cases:
  - >
    YAML merge-key spread: the env block is built via the `<<: *defaults`
    YAML merge syntax where `*defaults` contains LD_PRELOAD. A check
    that only scans literal object keys in the local block misses it.
    Rule must follow the merge through to the resolved key set, and
    when the analyser cannot statically resolve the anchor must emit
    an "unresolved-spread" factor rather than silently passing.
  - >
    Inherited env from parent process: the child config block does NOT
    override LD_PRELOAD (so a local-only scan misses it), but the parent
    process set LD_PRELOAD before spawning. MCP clients vary on whether
    they inherit parent env. Rule must still flag a config that
    EXPLICITLY adds LD_PRELOAD; silent inheritance is a different
    rule concern (not in scope for a static source check).
  - >
    Relative-path PATH injection: env.PATH = "./bin:/usr/bin". Looks
    benign (a relative entry is "locally-scoped"), but if the server
    chdirs into an attacker-controlled directory before shelling out,
    the ./bin prefix resolves to attacker binaries. Rule flags any
    PATH override — a reviewer can dismiss the relative-only variant
    manually after confirming the cwd.
  - >
    Non-absolute LD_PRELOAD / DYLD_INSERT_LIBRARIES: the attacker sets
    LD_PRELOAD = "evil.so" without a /. On Linux with a sufficiently
    permissive loader / a setuid-cleared process this still resolves
    via the library search path. Rule flags any LD_PRELOAD regardless
    of absolute-vs-relative — the primitive is the env key, not the
    path format.
  - >
    Sensitive-key allowlist bypass via case mutation: LD_Preload, Ld_Preload
    etc. On Linux env keys ARE case-sensitive so the lower-case variant
    is a different variable and is typically a no-op — BUT the rule must
    still flag the case-mutated forms because on Windows env names are
    case-insensitive and the same string works there. The charter's
    strategy is case-insensitive matching with a "case-mutated" factor
    noted when the key does not equal its canonical form.

edge_case_strategies:
  - yaml-merge-spread-warning
  - explicit-override-in-scope
  - path-override-flag-all
  - library-hijack-any-path
  - case-insensitive-key-match

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - risky_env_key_identified
    - risk_class_classified
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    MCP clients universally enforce a strict env-key allowlist (the
    SAFE_ENV_KEYS registry or equivalent) before passing a config's
    env block to the spawned server process. Claude Code and Cursor
    did NOT do this as of CVE-2026-21852 disclosure — the CVE remains
    actionable until all major clients ship the allowlist filter by
    default.
---

# L11 — Environment Variable Injection via MCP Config

**Author:** Senior MCP Threat Researcher.
**Applies to:** MCP server source code that embeds, generates, or writes
an MCP configuration literal whose `env` block sets a key on the L11
dangerous-key registry.

## What an auditor accepts as evidence

CVE-2026-21852 assessors accept:

1. **Context proof** — the finding names the object literal (with a
   `{kind:"source", file, line, col}` Location) containing the
   `mcpServers` key and an env child block.

2. **Risky-key proof** — the evidence states WHICH key fired and WHICH
   risk class it belongs to:
   - `library-hijack` — LD_PRELOAD / DYLD_INSERT_LIBRARIES
   - `runtime-injection` — NODE_OPTIONS / PYTHONPATH / PYTHONSTARTUP
   - `path-override` — PATH / PATHEXT
   - `proxy-mitm` — HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
   - `api-endpoint` — ANTHROPIC_API_URL / OPENAI_API_BASE

3. **Filter-absent proof** — the finding notes whether a filter could
   have accepted the safe keys (PORT, HOST, LOG_LEVEL, NODE_ENV) while
   rejecting the risky entry — a single allowlist filter would have
   stopped the attack.

4. **Impact statement** — the CVE-specific scenario tied to the class:
   native-code RCE (library-hijack / runtime-injection), credential
   exfiltration (api-endpoint), MITM (proxy-mitm), binary-resolution
   hijack (path-override).

## Relation to L4

L4 covers the MCP config's command/args primitives AND the API-base
env redirect. L11 covers ALL risky env keys with a richer risk-class
taxonomy. The two rules overlap INTENTIONALLY on api-base overrides —
a finding under whichever risk domain (supply-chain / insecure-config)
the reviewer is searching in. L11 alone covers the library-hijack and
runtime-injection primitives.

## Why confidence is capped at 0.85

Same rationale as L4 — the config literal may be test data or a
template the wrapping process will re-validate. The cap at 0.85
preserves a 0.15 reserve rather than overclaiming on static evidence.
