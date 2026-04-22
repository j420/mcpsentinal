---
rule_id: O10
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: MITRE-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. Behavioural
      telemetry that exceeds stated functionality is a persistent
      exfiltration channel: over time, the aggregated fingerprint
      identifies the user, machine, and environment a tool runs in.
  - kind: spec
    id: OWASP-MCP04
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. Surface
      enumeration (OS / arch / hostname / username / network
      interfaces / installed software versions / device IDs)
      transmitted off-box is the highest-volume background
      exfiltration primitive in the MCP ecosystem.
  - kind: paper
    id: breached-company-2026-77pct-leak
    url: https://breached.company/2026-ai-data-leak-report
    summary: >
      Breached.Company 2026: 77% of employees leak corporate data
      through AI tools. Unbounded telemetry inside agent tools is
      the mechanism; O10 targets the code pattern.
  - kind: paper
    id: gitguardian-secrets-sprawl-2026
    url: https://www.gitguardian.com/state-of-secrets-sprawl
    summary: >
      GitGuardian "State of Secrets Sprawl 2026" — AI-service-
      adjacent secret leaks surged 81% YoY. Ambient harvesting by
      helper tools (including MCP servers) is a named cause.
  - kind: paper
    id: lakera-year-of-the-agent-2025-q4
    url: https://www.lakera.ai/year-of-the-agent
    summary: >
      Lakera "Year of the Agent" (Q4 2025). Documents behavioural
      profiling via agent interaction traces and tool-usage
      frequency — the telemetry channel O10 detects statically.

lethal_edge_cases:
  - >
    OS / architecture / hostname / username harvesting —
    `os.hostname()`, `os.arch()`, `os.platform()`, `os.userInfo()`,
    `os.networkInterfaces()`, `process.arch`, `process.platform`,
    followed by a network-send or tool response. The server
    enumerates host identity beyond what the tool's stated
    purpose requires.
  - >
    Installed-software / dependency-version enumeration —
    `process.versions`, `require("./package.json").dependencies`,
    `exec("npm ls")`, Python `pkg_resources.working_set`,
    `pip freeze`. When paired with a network sink, the payload
    allows downstream CVE-targeting.
  - >
    Network-interface / IP / MAC harvesting — `os.networkInterfaces()`
    iterated for `.mac` / `.address`, `getifaddrs`, `netifaces.ifaddresses`.
    Hardware-identifier fingerprinting leaks location and
    device identity.
  - >
    Tool-usage timestamp + frequency logging — per-invocation
    `Date.now()` / `new Date()` combined with counters written
    to a cross-session store (module-level `Map`, filesystem,
    remote HTTP). Produces a behavioural fingerprint over time.
  - >
    Device-identifier harvesting — `machine-id`, `hwid`, fingerprint
    library calls (`fingerprintjs`, `@fingerprintjs/*`), reading
    `/etc/machine-id`, Windows Registry `MachineGuid`, macOS
    `ioreg -rd1 -c IOPlatformExpertDevice`. Persistent,
    non-rotatable device identity.

edge_case_strategies:
  - surface-enumeration-vocabulary
  - exfil-sink-cross-reference
  - telemetry-endpoint-or-tracking-pixel
  - consent-check-demotion
  - honest-refusal-no-network-egress

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - surface_enumeration_observed
    - transmission_off_box_observed
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP clients enforce a declared-telemetry capability with a
    user-approval gate, AND the MCP spec requires servers to
    list every OS / hardware / dependency enumeration primitive
    they call as part of their declared capabilities. Neither
    exists as of 2026-04.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# O10 — Privacy-Violating Telemetry

## Threat Model

A "helpful" MCP tool silently collects OS / arch / hostname /
username / network interfaces / installed software versions /
device identifiers / tool-usage timestamps, and transmits them
to an analytics endpoint or tracking pixel.

Distinction from **O5 (Env-Var Harvesting)**: O5 detects explicit
enumeration of `process.env`. O10 detects *surface-level host
fingerprinting* — the API calls that identify the user's box —
combined with a transmission sink.

Distinction from **O6 (Error Fingerprinting)**: O6 detects leakage
via error responses. O10 detects INTENTIONAL telemetry collection
and transmission, absent of any error path.

## Detection Strategy

The gather step walks the AST for three shapes:

1. **Telemetry enumeration + network sink** — the enclosing
   function reads ≥1 identifier from the `TELEMETRY_SURFACES`
   vocabulary (OS / host / network / software / device kinds)
   AND calls a network-send primitive (`fetch` / `axios` /
   `http.post` / bulk-header setters).
2. **Tracking pixel** — an `<img>` URL (or `src=` string) with a
   network-reachable host, embedded in a tool response body.
3. **Shared exfil-sink cross-reference** — if the enclosing
   function contains a bulk `process.env` read (env-var kind
   from `_shared/data-exfil-sinks.ts`) AND a telemetry surface
   read AND a network sink, confidence lifts.

## Honest-Refusal Gate

If the source contains no network-send primitive (no fetch /
axios / http.request / net.Socket.write / websocket), the rule
returns immediately. Pure compute-only servers never fire.

A consent-check demotion applies: if the enclosing function is
gated on an identifier matching `telemetryEnabled`, `consent`,
`optIn`, `allowTelemetry`, the finding is demoted (negative factor).

## Confidence Cap

**0.80** — surface enumeration paired with a network sink is a
structurally strong signal. Legitimate telemetry with explicit
opt-in does exist; the cap plus the consent-check demotion
preserves reviewer headroom for that case.
