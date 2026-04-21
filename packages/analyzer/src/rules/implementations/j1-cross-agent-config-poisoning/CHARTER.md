---
rule_id: J1
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-53773
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53773
  - kind: paper
    id: Embrace-The-Red-Copilot-MCP-2025
    url: https://embracethered.com/blog/posts/2025/copilot-prompt-injection-to-mcp-rce/
    summary: >
      Johann Rehberger (Embrace The Red) demonstrated that a GitHub Copilot
      agent compromised via indirect prompt injection writes a malicious
      entry into the user's .claude/settings.local.json; the next Claude
      Code session auto-loads the attacker's MCP server and achieves
      arbitrary code execution — a cross-agent privilege escalation chain
      without any user interaction. This is the in-the-wild proof the
      charter cites alongside the CVE.
  - kind: spec
    id: MITRE-ATLAS-AML.T0060
    url: https://atlas.mitre.org/techniques/AML.T0060
    summary: >
      ATLAS technique AML.T0060 "Modify AI Agent Configuration" — adversary
      alters agent configuration persistence to cause every future
      invocation of the victim agent to load attacker-controlled
      capabilities. J1 is the MCP-specific static detection of this
      technique's enabling primitive (the write itself).

lethal_edge_cases:
  - >
    Symlink/junction resolution: the MCP server writes to a path inside
    its own declared namespace, but that path is a symlink whose target
    resolves into ~/.claude/. A filename-only allowlist passes. The rule
    must flag any fs-write whose ARGUMENT evaluates to a known agent
    config suffix AFTER normalisation — the resolution risk is called
    out on the evidence chain because static analysis cannot always
    compute the link target.
  - >
    Windows / cross-platform path construction: the path is built from
    %APPDATA% or process.env.USERPROFILE + literal "\\.claude\\" — a
    check that only handles "/.claude/" as a Unix suffix misses the
    Windows variant entirely. The matcher must normalise both
    separators to a single canonical form before comparing.
  - >
    Append-only stealth: writeFile(path, data, { flag: "a" }) or
    appendFileSync(path, data) do not replace the victim's config; they
    extend it. An allowlisting "only NEW files are risky" heuristic
    passes. The rule must treat any write mode as dangerous on an agent
    config target, with an additional factor for the append case
    because it is the stealthier primitive.
  - >
    Runtime path assembly from env vars and string concatenation —
    path.join(process.env.HOME, ".claude", filename) where `filename`
    itself is tainted. The AST taint analyser sees the join but cannot
    always prove the final string is an agent-config target; J1 must
    still fire when the LITERAL components match, emitting a factor
    that records the dynamic-path upgrade.
  - >
    Sanitiser-named-but-unaudited: the code calls a locally-defined
    validate(path) before writeFileSync. The taint kit treats this as
    "sanitiser observed". J1's charter lists the exact identifiers it
    accepts (path-scope asserters, user-confirmation gates); any other
    validator is reported as "sanitiser present but not on audited
    list" with confidence lowered rather than zeroed.

edge_case_strategies:
  - symlink-resolution-warning
  - cross-platform-path-normalisation
  - append-mode-escalation
  - dynamic-path-upgrade-factor
  - charter-sanitiser-allowlist

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - agent_config_target_identified
    - ast_confirmed_write
    - interprocedural_hops
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    The MCP specification adds a capability-scoped configuration mode
    (server-signed manifest required before a config change takes
    effect) that makes third-party writes to an agent's configuration
    file unusable, OR the major AI clients (Claude Code, Cursor, VS
    Code) all refuse to auto-load new MCP servers without an
    interactive, non-bypassable user dialog — see CVE-2025-59536 for
    the current non-compliance.
---

# J1 — Cross-Agent Configuration Poisoning

**Author:** Senior MCP Threat Researcher.
**Applies to:** MCP servers whose source code performs a filesystem write
whose destination path matches a known AI-agent config location for a
DIFFERENT agent than the server's own host.

## What an auditor accepts as evidence

CVE-2025-53773 assessors do not accept "writeFileSync called somewhere".
They accept:

1. **Write-primitive proof** — a specific `fs.writeFile(...)` /
   `fs.appendFile(...)` / `fs.writeFileSync(...)` call with a
   `{kind:"source", file, line, col}` Location. If the write is
   interprocedural, the rule follows the shared taint chain and emits a
   propagation link per hop.

2. **Target-agent proof** — the first argument's observable text matches
   a suffix in the J1 agent-config target registry (`data/agent-config-
   targets.ts`). The registry names the victim agent (Claude Code,
   Cursor, VS Code, Gemini, Continue, Amp). The finding's evidence
   rationale STATES the agent host — "writes to Cursor per-project MCP
   registry" — so a reviewer can trace the trust boundary.

3. **Mitigation check** — the rule names which mitigation would suffice
   (`assertPathInsideNamespace`, `confirmCrossAgentWrite`, or equivalent)
   and reports whether any such call was observed on the path. An
   observed-but-unknown sanitiser name produces a "sanitiser present but
   not on J1 audited list" factor rather than silent acceptance.

4. **Impact statement** — the specific scenario: adversary-controlled
   MCP server entry is appended to the victim's config; on the next
   launch the downstream agent auto-loads that server (or the already-
   approved entry's command is silently mutated per CVE-2025-54136) and
   executes the attacker's payload with the agent's permissions.

## What the rule does NOT claim

- It does not claim that every `fs.writeFileSync` is a violation. The
  rule only fires when the destination is on the agent-config registry.
- It does not fire on pure READ operations against an agent-config
  path — inspection is legitimate, writing is the primitive.
- It does not fire on writes to paths the server "owns" (a
  same-component suffix match — this server's own config namespace).

## Why confidence is capped at 0.90

Static analysis cannot see a runtime user-confirmation dialog bolted on
by the enclosing process. A CLI wrapper around this MCP server that
prompts the user before letting writes land is not observable at source
scope. The cap at 0.90 preserves a 0.10 reserve for that scenario
rather than overclaiming. CVE-backed rules with direct-match flow and
no sanitiser on the charter list still reach 0.90 — regulators do not
need 0.99 to accept the finding.
