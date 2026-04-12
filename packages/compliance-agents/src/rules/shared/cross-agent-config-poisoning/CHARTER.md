# Rule Charter: cross-agent-config-poisoning

**Author:** Senior MCP Threat Researcher persona
**Engineer:** Senior MCP Security Engineer persona
**Severity:** critical
**Frameworks satisfied:** OWASP MCP10, OWASP ASI04, CoSAI T6/T11, MAESTRO L7, MITRE AML.T0060

## Threat model

A compromised MCP server writes into other agents' configuration paths
(`.claude/`, `.cursor/`, `.gemini/`, `~/.mcp.json`, `mcpServers.json`).
The attacker thereby installs persistence in *adjacent* AI agents on
the same machine — a one-server compromise becomes a workstation-wide
RCE because every other agent now loads the attacker's MCP server on
next start.

This is a real-world technique demonstrated by Embrace The Red (2025)
and corresponds to MITRE ATLAS AML.T0060 (Modify AI Agent Configuration).

## Real-world references

- **Embrace The Red (2025)** — cross-agent config poisoning chain.
- **CVE-2025-53773** — GitHub Copilot RCE via cross-agent injection.
- **MITRE AML.T0060** — Modify AI Agent Configuration technique.

## Lethal edge cases

1. **Filesystem-write tool with a parameter typed as a path** AND no
   root containment to the server's own working directory.
2. **Tools whose declared roots include `~` or `/`** — broad enough to
   reach other agents' config dirs.
3. **Output schemas that allow arbitrary path strings** to be returned
   to the AI client.
4. **Source code paths that join() user input into config-style file
   names** without normalization.
5. **Servers that bundle a `setup` or `install` tool** that mutates
   global config directories as part of "initialization".

## Evidence the rule must gather

- Tools whose capability graph node includes `accesses-filesystem` AND
  `writes-data`.
- Declared roots: any whose URI is broader than the server's own dir.
- The set of tool parameters classified as `file_path` semantic.

## Strategies

- `config-drift`
- `supply-chain-pivot`
- `privilege-chain`

## Judge contract

Confirm only when `facts.broad_filesystem_writers` is non-empty AND
the verdict references a tool in that list AND the tool has no root
containment narrower than the user's home directory.

## Remediation

Constrain all filesystem-writing tools to a containment root that the
server controls. Never declare `/` or `~` as a root. Validate that
write paths begin with the containment root after symlink resolution.
Reject any path containing components like `..` or absolute prefixes
that escape the root.

## Traceability (machine-checked)

rule_id: shared-cross-agent-config-poisoning
threat_refs:
- EMBRACE-THE-RED-CROSSAGENT-2025
- CVE-2025-53773
- MITRE-AML-T0060
strategies:
- config-drift
- supply-chain-pivot
- privilege-chain
