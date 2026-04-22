---
rule_id: Q13
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-6514
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6514
  - kind: spec
    id: OWASP-MCP10
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP10 Supply Chain. Unpinned bridge-package
      invocations (npx mcp-remote, uvx mcp) hand control of the
      executed code to whatever the registry currently serves,
      without an integrity check. CVE-2025-6514 documented an RCE
      in mcp-remote at CVSS 9.6; pinning would have blocked it.
  - kind: paper
    id: ALEX-BIRSAN-DEPENDENCY-CONFUSION
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Dependency-confusion primer (Alex Birsan, 2021). The exact
      class of attack Q13 guards against at the MCP bridge layer.

lethal_edge_cases:
  - >
    Unpinned `npx mcp-remote` / `npx mcp-proxy` / `npx mcp-gateway`
    / `npx @modelcontextprotocol/...` invocation in a shell command
    literal. Attackers publish a malicious version; the next npx
    fetch runs it.
  - >
    Unpinned `uvx mcp-*` / `uvx fastmcp` invocation. Same class,
    Python / uv side.
  - >
    Package-manifest declaration with `^`, `~`, `*`, or `"latest"`
    range for an MCP bridge package — resolves to whatever the
    registry returns, bypassing deliberate pinning.
  - >
    spawn('npx', ['mcp-remote']) / exec('npx mcp-proxy') — the
    same supply-chain risk, just expressed via child_process
    rather than a direct shell literal. Match on the argument
    list.
  - >
    Legitimate pinned invocation — `npx mcp-remote@1.2.3` /
    `"mcp-remote": "1.2.3"`. The rule classifies the version
    suffix so a pinned invocation does not fire.

edge_case_strategies:
  - shared-bridge-sinks-vocabulary
  - npx-uvx-shell-scan
  - child-process-arg-scan
  - manifest-range-loose-match

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - unpinned_bridge_invocation_observed
    - cve_precedent_available
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP ecosystem ships a signed-package-only policy for
    bridge packages, OR the ecosystem manifests (npm, PyPI) allow
    immutable-by-default package versions. Neither is current as
    of 2026-04.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - add-noop-conditional
  - reorder-object-properties
mutations_acknowledged_blind:
  - rename-danger-symbol
---

# Q13 — MCP Bridge Package Supply Chain Attack

## Threat Model

The most common MCP examples use `npx mcp-remote`, `uvx fastmcp`,
or `@modelcontextprotocol/server-...` packages pulled straight
from npm / PyPI with no version pin. CVE-2025-6514 demonstrated
a 9.6-CVSS RCE in mcp-remote at the point of execution. The
attacker does not need to compromise the user — they only need
to publish a malicious version to the registry and wait for the
next unpinned fetch.

Q13 detects four shapes: shell command literals with unpinned
`npx` / `uvx` invocations, child_process.spawn/exec calls with
the same unpinned arguments, and loose semver ranges (`^`, `~`,
`*`, `"latest"`) for known bridge packages in any JSON-like
object literal.

## Detection Strategy

AST pass over source code. String literals are tokenised into
command segments; if the tokens include a known bridge-package
name AND no version pin (`@x.y.z`) or a loose range, the match
fires. child_process calls are inspected for argument shapes.

## Confidence Cap

**0.80** — static analysis cannot be 100% sure the shell
literal runs (may be dead code); cap holds reviewer headroom.
