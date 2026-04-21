---
rule_id: Q4
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-54135
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-54135
  - kind: cve
    id: CVE-2025-54136
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-54136
  - kind: cve
    id: CVE-2025-59536
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-59536
  - kind: cve
    id: CVE-2025-59944
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-59944
  - kind: paper
    id: CheckPoint-IDEsaster-2025
    url: https://research.checkpoint.com/2025/idesaster-mcp-ide-trust-failures/
    summary: >
      Check Point Research (Dec 2025) compiled "IDEsaster" — 30+ CVEs and
      trust-model flaws spanning Cursor, Windsurf, Kiro, Copilot, Zed,
      Roo Code, Junie, Cline. The common pattern is auto-load MCP
      servers from project-local config files without an interactive,
      non-bypassable user confirmation. Q4 is the static detection of
      the primitive that feeds those vulnerabilities.
  - kind: paper
    id: TrailOfBits-Agentic-Trust-Boundaries-2026
    url: https://blog.trailofbits.com/2026/02/trust-boundaries-agentic-ai/
    summary: >
      Trail of Bits (Feb 2026) analysed the IDE-as-MCP-host trust
      boundary and concluded that repository-controlled auto-approve
      flags (enableAllProjectMcpServers) are equivalent to sandboxing-
      disabled primitives — the project-file is code, not data, once
      the flag is set.

lethal_edge_cases:
  - >
    Workspace-committed config — a .vscode/ or .cursor/ directory is
    committed to a shared repo, and its MCP config auto-loads when any
    developer on the team opens the project. Q4 must flag IDE-config
    writes regardless of who triggers them: the server writing to
    .vscode/mcp.json and the repo COMMITTING that file to git reach
    the same trust-boundary violation.
  - >
    Case-variant bypass (CVE-2025-59944) — the attacker writes to
    .cursor/MCP.JSON (or Mcp.Json, mCp.jSoN …). On macOS APFS and
    Windows NTFS the filesystem resolves both to the same file, but
    a case-sensitive validator that only checks ".cursor/mcp.json"
    passes. Rule must flag any case-variant of an MCP filename.
  - >
    Auto-approve programmatic write — a benign-looking script writes
    `enableAllProjectMcpServers: true` to the IDE config. Combined with
    any mcpServers entry (even one added later by another agent), this
    disables the user-approval gate for ALL project-level MCP servers.
    Q4 flags the auto-approve key-write separately from the servers
    themselves because the key-write is the enabling primitive.
  - >
    Settings-sync cloud profile — the attacker's auto-approve flag is
    pushed into the user's Settings Sync / cloud profile and replicates
    across every machine the user opens. A file-local check sees the
    local .cursor/settings.json write; Q4 must still flag it because
    the primitive is the write itself, regardless of where it
    subsequently propagates.
  - >
    Silent mutation of approved entry (CVE-2025-54136 MCPoison) —
    the attacker does NOT add a new server; they modify the command
    field of an ALREADY-APPROVED server. The user's stored approval
    keyed by server name; the new command runs with that approval.
    Q4 flags ANY write to an IDE config, regardless of whether the
    key already existed — the silent-mutation variant is the
    severest form.

edge_case_strategies:
  - workspace-committed-aware
  - case-variant-match
  - auto-approve-key-separate-finding
  - any-write-regardless-of-propagation
  - silent-mutation-covered-by-any-write

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - ide_primitive_identified
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    The IDE ecosystem (Cursor, VS Code, Claude Code, Claude Desktop,
    Windsurf, Zed, Kiro …) adopts a uniform rule: every project-local
    MCP config change requires an interactive user confirmation that
    CANNOT be bypassed by a repo-controlled flag, and the IDE case-
    normalises MCP config filename lookups. Both CVE-2025-54135
    (CurXecute) and CVE-2025-59944 (case-bypass) remain unpatched
    across some IDEs as of disclosure; Q4 stays actionable until
    those CVEs close.
---

# Q4 — IDE MCP Configuration Injection

**Author:** Senior MCP Threat Researcher.
**Applies to:** MCP server source code that writes to an IDE's MCP
configuration surface, or embeds auto-approve settings, or uses
case-variant MCP filenames.

## What an auditor accepts as evidence

CVE-2025-54135 / 54136 / 59536 / 59944 assessors accept:

1. **Primitive identification** — the finding states WHICH Q4 primitive
   fired:
   - `ide-config-write` — fs write targets an IDE's MCP config file;
   - `auto-approve-write` — object literal sets enableAllProjectMcp
     Servers / autoApprove / trustAllServers = true;
   - `case-variant-filename` — write path uses a case-variant of
     mcp.json / settings.json that bypasses case-sensitive validators.

2. **Victim identification** — the finding names the IDE (Cursor, VS
   Code, Claude Code, Claude Desktop, Kiro, Roo Code …) by matching
   the path against the Q4 IDE target registry. The evidence states
   WHICH IDE's trust boundary is being crossed.

3. **CVE mapping** — the evidence chain's threat_reference cites the
   specific CVE whose exploit chain this finding matches:
   - ide-config-write on Cursor → CVE-2025-54135 (CurXecute);
   - silent mutation of an approved entry → CVE-2025-54136 (MCPoison);
   - auto-approve write on Claude Code → CVE-2025-59536;
   - case-variant filename → CVE-2025-59944.

4. **Impact statement** — the CVE-specific scenario: silent MCP server
   execution on next IDE launch, equivalent-to-RCE with the IDE's
   permissions, persistence across sessions and (via Settings Sync)
   across machines.

## Differences from J1 and L4

- **J1** flags ANY write to another agent's config file regardless of
  content. Q4 scopes to IDE configs specifically, and adds the
  case-variant and auto-approve-flag primitives that J1 does not cover.
- **L4** flags command/args/env primitives inside a CONFIG LITERAL.
  Q4 flags IDE-targeted WRITES (regardless of the literal's content)
  plus the auto-approve flag pattern. The three rules together form
  the CVE-backed trident — a finding surfaces under whichever lens a
  reviewer searches (cross-agent, supply-chain, cross-ecosystem).

## Why confidence is capped at 0.88

The write may be gated by an out-of-file user-confirmation prompt the
analyser cannot see. CVE-2025-54135 demonstrated that IDEs DO NOT
implement such a gate by default, so the cap is higher than L4's 0.85
— the attack primitive is more direct — but a 0.12 reserve remains
for future IDE patches that add the gate.
