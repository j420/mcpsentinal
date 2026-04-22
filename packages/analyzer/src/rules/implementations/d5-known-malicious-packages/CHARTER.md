---
rule_id: D5
interface_version: v2
severity: critical

threat_refs:
  - kind: incident
    id: ua-parser-js-2021
    url: https://github.com/advisories/GHSA-pjwm-rvh2-c87w
    summary: >
      ua-parser-js compromise (October 2021). A maintainer account
      takeover led to three malicious releases (0.7.29, 0.8.0, 1.0.0)
      that installed cryptominers and infostealers via postinstall
      hooks. 7-8 million weekly downloads at compromise time. The
      incident established the pattern the D5 blocklist exists to
      detect: exact-match package names that have been confirmed as
      malicious by at least one authoritative advisory.
  - kind: incident
    id: event-stream-2018
    url: https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident
    summary: >
      event-stream / flatmap-stream (November 2018). Malicious
      flatmap-stream subdependency shipped by a new "volunteer"
      maintainer who gained commit rights to event-stream. The payload
      targeted the copay wallet's private keys. Classic illustration
      that a package must be treated as malicious once a credible
      disclosure identifies it — removing the publish from the
      registry does NOT remove it from already-resolved lockfiles.
  - kind: incident
    id: colors-faker-2022
    url: https://snyk.io/blog/open-source-npm-packages-colors-faker/
    summary: >
      colors-js and faker protestware (January 2022). The maintainer
      shipped intentionally-malicious versions (infinite loops, gibberish
      output) to protest corporate usage. Demonstrated that a package's
      "known-malicious" status is a point-in-time claim and must be
      carried in a versioned advisory list, not just a registry removal.
  - kind: incident
    id: socket-mcp-squat-wave-2025
    url: https://socket.dev/blog/typosquat-mcp-sdk-wave
    summary: >
      Socket.dev (2025) documented the first wave of MCP-ecosystem
      typosquats: @mcp/sdk, mcp-sdk, fastmcp-sdk shadowing the official
      @modelcontextprotocol/sdk. Each variant carried postinstall scripts
      exfiltrating environment variables. This is the direct source for
      D5's MCP-ecosystem entries.
  - kind: spec
    id: OWASP-MCP10-Supply-Chain
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP10 — Supply Chain. Explicitly requires blocking
      dependencies listed in authoritative malicious-package databases at
      install time. D5 is the static-analysis mirror of that runtime control.
  - kind: spec
    id: SOC-2-CC-6.8-Supply-Chain
    url: https://www.aicpa-cima.com/resources/download/soc-2
    summary: >
      SOC 2 Common Criteria CC6.8 — The entity implements policies for
      security throughout the software development life cycle including
      third-party software. An exact-match malicious-package detection
      is a primary automated control that SOC 2 auditors accept as
      evidence of CC6.8 compliance.

lethal_edge_cases:
  - >
    Cyrillic-homoglyph package name. An attacker registers `еvent-stream`
    (Cyrillic 'е' instead of Latin 'e'). The D5 blocklist only
    contains Latin-lowercase keys, so a naive lookup misses the
    homoglyph. D5's implementation normalises candidate names through
    the shared Unicode confusables pipeline before lookup — any
    codepoint-drifted name is rechecked against the blocklist after
    normalisation. Cross-references A6 (Unicode Homoglyph Attack) for
    the root cause; D5 contributes the blocklist half of the signal.
  - >
    Scope-shadow of official MCP packages. `@npmjs/mcp-sdk` is not in
    the same scope as `@modelcontextprotocol/sdk` but looks authoritative
    (the scope is the npm corporate account — which never publishes MCP
    SDK material). The blocklist records the exact scoped name; D5 does
    not do fuzzy scope matching (that is D3's job) — but documented
    scope-shadows are legitimate entries in the confirmed-malicious list.
  - >
    Hyphenation-variant typosquat. `react_router` (underscore) vs
    `react-router` (dash). Both are valid npm name shapes. The blocklist
    carries the exact-match name of the known-bad variant only; the
    reviewer must add new known-bad variants explicitly — D5 is not a
    fuzzy-matcher. This is the charter's decision to keep D5 at very
    high confidence by trading off against D3's recall.
  - >
    Withdrawn advisory / reinstated package. A package appears in a
    historical advisory but has since been re-taken-over by a reputable
    maintainer (rare but real). The blocklist should be pruned in the
    same PR that confirms the re-takeover; pending that review, D5 emits
    a finding and the reviewer can add a legitimate-fork-equivalent
    exception.
  - >
    Package installed via manifest override / resolution. A malicious
    package may not appear as a direct dep but be pinned via npm overrides
    or pip constraints. D5 scans context.dependencies which contains the
    resolved closure; if the overrides did their job, D5 sees and flags
    the pinned version.

edge_case_strategies:
  - exact-match-lookup
  - unicode-normalise-before-lookup
  - explicit-variant-enumeration
  - advisory-driven-maintenance

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - confirmed_malicious_package_hit
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Every package registry (npm, PyPI, rubygems, cargo) implements
    real-time malicious-package blocking at resolve time, AND lockfile
    generators refuse to record a package flagged in any authoritative
    advisory. Under those conditions a malicious package cannot reach
    a consumer's manifest and D5 becomes redundant.
---

# D5 — Known Malicious Packages

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any dependency in `context.dependencies`. The blocklist is
the sole evidence source — no heuristics, no similarity.

## Relationship to D3 and DependencyAnalyzer engine

D3 (Typosquatting) fires on lexical similarity — fuzzy near-miss matches.
D5 fires on EXACT NAME or NORMALISED-UNICODE EXACT NAME matches. Same dep
can legitimately produce findings from BOTH rules. D5 is the higher-
confidence, harder-evidence claim.

The DependencyAnalyzer engine's D5 branch emits a legacy finding; the
engine dispatcher defers to this v2 rule when registered.

## Confidence cap: 0.95

The highest cap in this chunk. An exact-match hit on an authoritative
blocklist is as close to "known malicious" as static analysis gets —
we trust the source advisory. The 0.05 reserved space covers the
edge case of a rehabilitated package still listed for historical reasons.

## Vocabulary maintenance

`data/malicious-packages.ts` MUST cite an advisory URL for every entry.
New entries land through either:
- a PR that adds the advisory link and a one-sentence rationale, or
- a test fixture demonstrating the name shape is seen in the wild.

Never add "I suspect this is malicious" entries without public evidence.

## SOC 2 mapping

Because D5's evidence is exact-match against a cited advisory, SOC 2
auditors accept the finding as CC6.8 control output without additional
corroboration — the advisory IS the corroboration.
