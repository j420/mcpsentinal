---
rule_id: D2
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: OWASP-A062021-Vulnerable-Outdated-Components
    url: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
    summary: >
      OWASP Top 10 A06:2021 — Vulnerable and Outdated Components.
      Explicitly names "software component is unsupported or out of
      date" as the primary diagnostic. Unmaintained packages are the
      single largest category of exploitable software supply-chain
      risk because vulnerabilities discovered after abandonment are
      never patched.
  - kind: paper
    id: Left-Pad-2016-Incident
    url: https://www.davidhaney.io/npm-left-pad-have-we-forgotten-how-to-program/
    summary: >
      The left-pad incident (March 2016) demonstrated that even an
      11-line dependency can brick the JavaScript ecosystem when an
      unmaintained maintainer becomes an attack surface (removal,
      takeover, or account compromise). Abandonment is the necessary
      precondition — an actively maintained package's maintainer can
      respond to takeover attempts in real time; an abandoned one's
      cannot.
  - kind: incident
    id: Faker-2022-Protestware
    url: https://snyk.io/blog/open-source-npm-packages-colors-faker/
    summary: >
      The faker/colors.js protestware incidents (January 2022) showed
      that a package treated as abandoned by consumers (but still
      technically maintained) can be weaponised by its maintainer
      overnight. D2 surfaces the abandonment signal precisely so
      consumers are alerted before the takeover or protestware event
      occurs — a fresh publish-date is a proxy for an active human
      who would resist such a compromise.
  - kind: spec
    id: CoSAI-MCP-T6-Supply-Chain
    url: https://cloudsecurityalliance.org/research/working-groups/agentic-ai-security
    summary: >
      CoSAI MCP Security threat category T6 — Supply Chain. Abandoned
      packages are identified as a prime target for CoSAI-MCP-T6
      package takeover attacks because npm / PyPI maintainer-reset
      email flows assume an active maintainer; an abandoned account
      is exactly the gap an attacker exploits.
  - kind: spec
    id: ISO-27001-A.8.8
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.8 — Management of Technical
      Vulnerabilities. Abandonment is a structural vulnerability class
      even absent a specific CVE: the package cannot be patched.

lethal_edge_cases:
  - >
    Long-term-stable packages ("completed" software). Some packages
    legitimately reach a stable state and stop receiving updates
    because they are finished (classic: `left-pad`, numeric-constants,
    tiny well-scoped utilities). The rule uses age as a RISK signal,
    not a certainty — the evidence chain states the age in months
    and flags the package as "potentially abandoned, reviewer to
    confirm via repo activity / issue tracker" rather than asserting
    the package is dead.
  - >
    Fork-resurrection dependencies. `request` (abandoned) vs
    `@node-rs/request` (forked and maintained). The rule cannot
    traverse the fork graph statically; it fires on the abandoned
    parent and records that a maintained fork MAY exist. Remediation
    instructs the reviewer to search for a live fork or an alternate
    package.
  - >
    Internal / private dependencies with infrequent releases. An
    internal company package released once to a private registry and
    used happily for 2 years shows >12 months age — yet it is not
    abandoned, the team simply hasn't needed to modify it. The rule
    cannot distinguish private from public registries statically. The
    evidence chain records the age signal and leaves intent to the
    reviewer; this is also why confidence is capped at 0.70.
  - >
    last_updated missing or null. The DependencyAuditor may not have
    resolved a publish date (registry down, timeout). The rule MUST
    skip silently when last_updated is null — it never guesses. This
    is a coverage gap the AnalysisCoverage reporter surfaces, not a
    false-negative.
  - >
    Age bucket near the 12-month boundary. A package with last update
    13 months ago is technically abandoned by the threshold but
    almost certainly still viable. The rule uses a graduated age
    factor (higher adjustment for >36 months) so borderline cases do
    not dominate the score.

edge_case_strategies:
  - null-last-updated-silent-skip
  - age-graduated-factor
  - single-finding-per-dep

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - abandoned_age_over_threshold
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Package registries emit a first-class "maintenance status" field on
    every package (not a heuristic over publish dates) AND lockfile
    tools refuse to install from an abandoned manifest. Under those
    conditions the rule's heuristic is superseded by registry ground
    truth.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# D2 — Abandoned Dependencies

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any dependency whose `last_updated` is populated by the
scanner's DependencyAuditor.

## Relationship to DependencyAnalyzer engine

The DependencyAnalyzer engine emits a legacy D2 finding without an evidence
chain. When this v2 rule is registered the engine dispatcher defers the
engine finding (engine.ts lines 322-330) and this rule is the canonical
producer of D2 evidence.

## Age threshold

12 months (legacy threshold retained for continuity). The age bucket is
reported exactly in the chain so any downstream policy can apply a stricter
threshold without re-scanning.

## Confidence cap: 0.70

Abandonment is inherently fuzzy. A >12-month-old package can be:
- genuinely dead (high confidence in the finding);
- stable and complete (low confidence);
- an internal / private dep not meant for public consumption.

A 0.70 cap forces every D2 finding to be read as "investigate", not "block".
Reviewers tighten via `edge_case_strategies` in follow-up work.
