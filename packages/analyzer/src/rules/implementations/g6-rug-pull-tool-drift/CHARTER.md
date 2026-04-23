---
rule_id: G6
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: EmbraceTheRed-2025-MCP-Rug-Pull
    url: https://embracethered.com/blog/posts/2025/mcp-rug-pull/
    summary: >
      Johann Rehberger (Embrace The Red, 2025) demonstrated the MCP
      "rug-pull" attack: a server establishes trust with a stable,
      benign tool surface, gets approved by the user or included in
      an allowlist, then silently mutates — adding dangerous tools,
      rewriting descriptions, flipping destructiveHint annotations —
      in a subsequent release. Because MCP clients typically cache
      approval decisions against the server identifier, the mutation
      inherits the original trust grant. Every trust-on-first-use
      MCP client is vulnerable unless it explicitly re-prompts on
      tool-surface change. G6 is MCP Sentinel's structural detector
      for this temporal threat model.
  - kind: paper
    id: MCPoison-CVE-2025-54136
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-54136
    summary: >
      CVE-2025-54136 (Cursor MCPoison, 2025) — silent mutation of
      an already-approved MCP config persists across sessions without
      re-prompting. The CVE describes the client-side cache-integrity
      gap; G6 is the server-side telemetry that surfaces WHEN a rug
      pull has been attempted by detecting tool-surface drift from a
      prior scan baseline. (Listed in docs/cve-manifest.json under
      rule Q4; G6 shares the threat model.)
  - kind: spec
    id: OWASP-MCP02-Tool-Poisoning
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 — MCP02 Tool Poisoning. Rug-pull attacks are
      a temporal-variant tool-poisoning vector: the server poisons
      its own tool set only AFTER passing initial review. G6 extends
      MCP02 coverage from single-scan classification to across-scan
      drift detection.
  - kind: spec
    id: MITRE-ATLAS-AML-T0054
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. A rug pull adds
      new tool descriptions (which are injection surfaces the LLM
      reads) or modifies existing ones to carry injection payloads
      AFTER the tool has been approved. The ATLAS indirect-injection
      sub-technique applies to the newly-added or newly-mutated
      surface.
  - kind: paper
    id: MCP-Sentinel-Historical-Baseline
    url: https://github.com/j420/mcpsentinal/blob/main/agent_docs/detection-rules.md
    summary: >
      MCP Sentinel's architecture doc mandates a per-server historical
      baseline (tool-surface fingerprint from the previous scan) for
      temporal-signal rules. G6 is the canonical consumer of this
      baseline: without a prior-scan record, G6 is architecturally
      unable to fire — the rule emits no finding on the first scan
      of a server. This is the honest confidence choice, not a bug.

lethal_edge_cases:
  - >
    Tool count delta >5 in a single scan window — the server added
    more than five new tools since the last scan. An honest version
    bump rarely ships more than a handful of new tools at once; a
    sudden surge is a rug-pull signal. The rule counts only ADDED
    tools, not replaced or renamed ones.
  - >
    Dangerous tool added after a stable baseline — a new tool whose
    name or description implies command execution, file deletion,
    credential access, or network egress. Baseline comparison must
    persist across at least two prior scans (stable baseline
    requirement); a brand-new server that adds a dangerous tool on
    its second-ever scan is a less definitive rug-pull signal than
    the same addition on a server with a six-month stable history.
  - >
    Description hash changed on a security-critical tool — an
    approved tool's hash changed without a name change. This is the
    classic "tool keeps its name, its instructions quietly mutate"
    variant. The rule must compare the full canonical fingerprint
    (name + description + schema + annotations) tool-by-tool, not
    just compare counts.
  - >
    Entire tool set replaced — every tool's fingerprint changed
    (zero unchanged). This is a degenerate rug-pull where the
    attacker repurposes the server identifier for a new product.
    The rule emits a high-severity finding with a maximum-drift
    classifier.
  - >
    Annotations flipped from destructiveHint:true to
    destructiveHint:false (or readOnlyHint flipped the wrong way)
    on an approved tool — a rug-pull variant where the tool's
    capability claim is mutated to bypass the client's approval UI.
    The rule reads the annotations surface from the fingerprint and
    flags false-positive flips.
  - >
    No baseline available — first scan of this server. The rule
    MUST NOT fire (no comparison possible). The charter explicitly
    documents this: G6 is context-dependent and honest about the
    absence of evidence. Emitting a finding on a first-scan server
    would be a fabricated signal.

edge_case_strategies:
  - tool-count-delta-threshold
  - dangerous-new-tool-classifier
  - fingerprint-hash-diff
  - annotation-flip-detection
  - baseline-absence-skip

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - baseline_reference
  location_kinds:
    - tool
    - capability

obsolescence:
  retire_when: >
    MCP clients universally re-prompt the user on every tool-surface
    change (even when the server identifier is unchanged) AND the
    MCP spec mandates a signed server-content-hash that the client
    must verify before every tools/list refresh. Under those
    conditions rug-pull attacks cannot inherit prior trust, so G6's
    detection layer becomes redundant.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# G6 — Rug Pull / Tool Behavior Drift

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers for which the analyzer has access to a
previous-scan baseline. The primary carrier of the baseline is
`context.previous_tool_pin` (a `ServerToolPin` recorded by
`packages/analyzer/src/tool-fingerprint.ts`).

## Why G6 is context-dependent

G6 is the rule that most directly needs time. Every other rule in
the catalogue makes a claim from a single snapshot; G6 makes a claim
from the DIFFERENCE between two snapshots. The consequence is that
the rule behaves differently in three baseline states:

1. **No baseline (first scan)** — the rule DOES NOT FIRE. The charter
   is explicit about this: emitting a finding from a single scan
   fabricates a temporal signal that does not exist. The rule
   returns `[]` and the scan posture reports G6 as "insufficient
   data — first scan".

2. **One prior scan (weak baseline)** — the rule fires at reduced
   confidence. A single prior data point is not a stable baseline;
   the attacker could simply have shipped a new release between
   scan windows. The rule emits the finding at a floored confidence
   of ≤0.40 and names "weak-baseline-one-prior" as a factor.

3. **Stable baseline (two or more prior scans with unchanged
   fingerprint)** — the rule fires at normal confidence (≤0.80
   charter cap). "Stable" means the PRIOR TO most recent scan was
   also unchanged; a sudden change against a stable-for-two-scans
   baseline is the canonical rug-pull signal.

The analyzer currently exposes `context.previous_tool_pin`, a
single-prior-scan record. A future scanner enhancement will pass a
multi-scan history; until then G6 operates in the one-prior-scan mode
and caps confidence accordingly.

## What an auditor accepts as evidence

A tool-drift auditor (OWASP MCP02, MITRE ATLAS AML.T0054) will not
accept "tools changed". They will accept a finding that says:

1. **Diff proof** — the finding cites the specific tools that were
   added (tool-kind Locations for each), and for each added tool the
   name classifier result. The auditor opens both tool lists, counts
   the added tools, and confirms the names.

2. **Dangerous-classifier proof** — the finding enumerates which of
   the added tools the classifier considered dangerous (execute /
   delete / write / send / admin patterns) and why. The classifier
   is structural (a name-vocabulary check, not a prose reason).

3. **Impact statement** — concrete description: the client already
   trusts this server; the new tools inherit that trust without a
   fresh approval prompt. Subsequent invocations of the new tools
   execute under the established trust grant.

## Why confidence is capped at 0.80

The rule has partial visibility:

- the analyzer cannot distinguish an honest version upgrade from a
  deliberate rug-pull — intent is not statically observable;
- the prior baseline is a single-scan record in the current
  architecture, not a multi-scan stable history;
- the classifier for "dangerous new tool" is a name-vocabulary check
  and may miss tools that disguise intent in their naming.

Capping at 0.80 preserves explicit room for these limitations. The
remaining 0.20 signals: "temporal signal strong, reviewer should
inspect the server's release notes before concluding rug-pull intent."
