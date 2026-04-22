---
rule_id: D7
interface_version: v2
severity: high

threat_refs:
  - kind: paper
    id: Birsan-2021-Dependency-Confusion
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Alex Birsan (Feb 2021) "Dependency Confusion: How I Hacked Into
      Apple, Microsoft and Dozens of Other Companies". Collected $130k
      in bug bounties by publishing npm/PyPI packages with
      artificially-high version numbers (e.g. 9000.0.0, 10000.1.2)
      under the same name as internal private packages. Package
      managers preferred the public higher version, executing
      attacker-controlled install hooks inside corporate build
      environments.
  - kind: spec
    id: OWASP-MCP10-Supply-Chain
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP10 — Supply Chain. Dependency confusion is
      explicitly enumerated as a supply-chain compromise class.
  - kind: spec
    id: OWASP-ASI04-Agentic-Supply-Chain
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Security Initiative ASI04 — Agentic Supply Chain.
      Identifies dependency-confusion as a primary enabler of hostile
      code reaching an agent's runtime.
  - kind: spec
    id: CoSAI-MCP-T6-Supply-Chain
    url: https://cloudsecurityalliance.org/research/working-groups/agentic-ai-security
    summary: >
      CoSAI MCP Security T6 — Supply Chain Compromise. D7 is the
      automated static-analysis detection for the T6 "public-registry
      version takeover" sub-pattern.
  - kind: incident
    id: microsoft-apple-paypal-2021
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Microsoft, Apple, PayPal, Shopify, Tesla, Uber, and ~35 other
      Fortune-500 companies were demonstrated-compromised by Birsan's
      2021 research using the artificially-high-version technique.
      Multiple follow-on copycat attacks were documented through 2022-2024
      reinforcing that the technique remains live.

lethal_edge_cases:
  - >
    Legitimate high-version package. Some packages are legitimately at
    high major versions through heavy release cadence (Chrome-scheduler
    style, or projects using CalVer like `ubuntu`). The threshold
    treats ≥99 as suspicious, ≥999 as highly suspicious — reviewers
    tune based on the project's expected baseline. The evidence chain
    records the major version exactly so any downstream policy can
    apply a stricter threshold without re-scanning.
  - >
    Scoped vs unscoped. Birsan's canonical trick targets scoped
    packages — `@acme/internal-lib` at public version 9999.0.0. The
    rule applies ONLY to scoped packages (leading '@'). Unscoped
    packages with high versions are not automatically suspicious —
    they are public-by-design. This matches Birsan's original attack
    surface: the scope is the authentication signal.
  - >
    Calendar versioning (CalVer). Projects using YYYY.MM.DD or
    YYYYMMDD versioning trivially exceed the threshold. The rule
    records the version verbatim so a reviewer inspecting the finding
    can dismiss obvious CalVer. Note: Birsan's attacks used ordinary
    semver (9999.0.0), not CalVer, so this is a false-positive class
    rather than a detection gap.
  - >
    Private-registry pin is actively in place. A project with
    `@acme/internal-lib@9999.0.0` may be intentional — an internal
    package whose team lifts the major to bypass the attacker's
    technique (reverse Birsan). D7 cannot see the registry
    configuration; the evidence chain frames the finding as
    "investigate whether the manifest pins a registry scope" so the
    reviewer can confirm by inspecting `.npmrc` / `pip.conf`.
  - >
    Non-semver version strings. `git+https://github.com/...#main` does
    not parse as a major. The rule skips these entries — inferring
    "suspiciously high" from a git SHA is not meaningful. This is the
    correct silent-skip pattern; the coverage gap is surfaced by
    AnalysisCoverage.

edge_case_strategies:
  - scoped-package-only
  - major-version-tiered-threshold
  - silent-skip-non-semver

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - suspicious_major_version
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Every major package manager enforces scope-pinned registry resolution
    by default (opt-out rather than opt-in) AND lockfile formats encode
    the resolution scope cryptographically. Under those conditions the
    Birsan technique cannot substitute a public package for a scoped
    private one.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# D7 — Dependency Confusion Attack Risk

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Scoped packages (leading `@`) in `context.dependencies`.

## Threshold

- Major version ≥ 99: SUSPICIOUS (standard finding)
- Major version ≥ 999: HIGHLY SUSPICIOUS (amplified factor)

Derived from Birsan's original exploit versions (9000, 9999, 10000-range).

## Confidence cap: 0.80

The major-version threshold is a strong indicator but not a proof. The
0.20 head-room covers:
- legitimate high-version projects (rare for scoped packages);
- CalVer usage;
- the possibility that the manifest has a registry-scope pin the
  scanner cannot see.

## SOC 2 + ISO 27001 mapping

A D7 finding is direct SOC 2 CC6.8 and ISO 27001 A.5.21 evidence. The
remediation involves BOTH inspecting the public-registry page for the
candidate AND verifying the local `.npmrc` / `pip.conf` registry-scope
pin.
