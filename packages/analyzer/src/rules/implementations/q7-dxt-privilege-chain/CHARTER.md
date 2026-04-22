---
rule_id: Q7
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
  - kind: spec
    id: OWASP-MCP05
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP05 Privilege Escalation. Desktop
      extensions (DXT) and their browser-extension bridges cross
      privilege boundaries the user never sees. Auto-approve flags
      in the manifest promote every packaged tool to trusted
      status without a user gesture.

lethal_edge_cases:
  - >
    autoApprove flag in a DXT / MCP manifest — `"autoApprove": true`
    in package.json, manifest.json, or any .dxt bundle config
    promotes every packaged tool to trusted status without user
    confirmation. Matches CVE-2025-54136 (Cursor MCPoison) exactly.
  - >
    Browser-extension native-messaging bridge — `chrome.runtime.sendNativeMessage`,
    `browser.runtime.sendNativeMessage` invoked from extension code
    targeting an MCP / tool-server receiver. The extension
    inherits browser permissions AND bridges them into MCP-level
    authority.
  - >
    Electron ipcMain handler wired to an MCP tool — `ipcMain.handle(...)`
    whose handler directly calls a tool invocation. Grants renderer
    content access to the full MCP surface.
  - >
    DXT manifest JSON file present with suspicious flags — detection
    via file content in the analyzer's source_code context (JSON
    pretty-printed as text).

edge_case_strategies:
  - shared-dxt-sinks-vocabulary
  - auto-approve-flag-match
  - native-messaging-bridge-match
  - ipc-handler-mcp-match

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - dxt_privilege_bridge_observed
    - no_user_confirmation_gate
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP clients treat every manifest flag as untrusted and require
    per-tool user confirmation regardless, OR the DXT format adds
    signed-manifest attestation that clients enforce. Neither is
    current as of 2026-04.
---

# Q7 — Desktop Extension Privilege Chain (DXT)

## Threat Model

Cursor's `.cursor/mcp.json` + Claude Code's `.mcp.json` show that
a single config file can auto-start an MCP server before the user
has any chance to review it. Three disclosed CVEs in 2025
(CVE-2025-54135, CVE-2025-54136, CVE-2025-59536) demonstrate how
auto-approve flags and unverified extension-to-MCP bridges
convert a benign-looking config change into remote code
execution against the user's workspace.

Q7 statically detects the three ingress points:

1. `"autoApprove"` / `"auto_approve"` flag set to `true` in
   manifest-like JSON embedded in the source.
2. `chrome.runtime.sendNativeMessage` or `browser.runtime.sendNativeMessage`
   call targeting an MCP-related receiver.
3. `ipcMain.handle(...)` wired to a tool-invocation flow.

## Detection Strategy

Source-only structural detection. Zero regex. The manifest flag
search inspects every string literal that looks like a JSON
value assignment and the autoApprove key. For the JS / TS
patterns, it inspects CallExpressions against DATA_EXFIL_SINKS
"dxt-ipc" and "bridge-ipc" entries.

## Confidence Cap

**0.82** — three CVEs as precedent make this a high-confidence
detection; the remaining headroom covers legitimate admin
tooling that might justifiably use ipcMain for privileged
actions behind an explicit consent dialog.
