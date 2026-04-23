---
rule_id: D3
interface_version: v2
severity: high

threat_refs:
  - kind: paper
    id: Birsan-2021-Dependency-Confusion
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Alex Birsan (Feb 2021) demonstrated that package managers prefer
      higher-versioned public packages over private internal packages of
      the same name, enabling adversaries who publish typosquatted or
      namespace-colliding names on public registries to achieve remote
      code execution on corporate build environments. Typosquatting is a
      core vector because developer copy/paste of dependency names
      yields silent substitution of attacker-controlled packages.
  - kind: spec
    id: OWASP-MCP10-Supply-Chain
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 — MCP10 Supply Chain. Explicitly names
      typosquatted dependencies as a supply-chain compromise vector.
      An MCP server that installs a typosquatted package executes
      attacker code during postinstall or at import time, producing an
      RCE in the server's host environment.
  - kind: spec
    id: OWASP-ASI04-Agentic-Supply-Chain
    url: https://owasp.org/www-project-agentic-security-initiative/
    summary: >
      OWASP Agentic Top 10 — ASI04 Agentic Supply Chain. Identifies
      dependency typosquats as the primary enabler of malicious code
      entering an agent's runtime. Because agents execute tool calls
      on behalf of users with the server's authority, a single
      typosquatted dependency compromises all downstream agent
      invocations.
  - kind: spec
    id: ISO-27001-A.5.21
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.21 — Managing Information
      Security in the ICT Supply Chain. Requires processes to verify
      third-party suppliers (including package registries) and the
      components they deliver. A Damerau-Levenshtein-close match to a
      well-known popular package is a supply-chain anomaly that the
      control requires be detected and reviewed before the component is
      accepted.
  - kind: incident
    id: Socket-2025-MCP-squat-wave
    url: https://socket.dev/blog/typosquat-mcp-sdk-wave
    summary: >
      Socket.dev (2025) documented a wave of typosquats targeting
      @modelcontextprotocol/sdk — notably @mcp/sdk, mcp-sdk, fastmcp-sdk.
      Installed packages carried postinstall scripts that exfiltrated
      environment variables. The MCP-ecosystem typosquat cohort is the
      direct reason this rule carries a curated MCP target list.

lethal_edge_cases:
  - >
    Legitimate namespace fork — `lodash-es` is a real package within
    Damerau-Levenshtein distance 3 of `lodash`. A detector that fires
    purely on edit distance misclassifies it as a typosquat. The rule
    suppresses candidates listed in `legitimate-forks.ts` and
    down-weights candidates whose only extra content is a structural
    suffix like `-es`, `-fork`, `-pro`.
  - >
    Visual-confusable graphemes in ASCII — `rnistral` differs from
    `mistral` by substituting `rn` for `m`. Pure Damerau-Levenshtein
    scores distance 2 but doesn't flag this as "near" `mistral` with
    high confidence. The rule re-evaluates every <=2-distance candidate
    through `visuallyConfusableVariants` to catch the RN/M, CL/D, VV/W
    cohort.
  - >
    Scope-squat under a different scope — `@mcp/sdk` shadows the
    official `@modelcontextprotocol/sdk` via scope replacement rather
    than substring edits. Character-level Levenshtein would consider
    these far apart. The rule runs a scope-squat check on any dependency
    whose UNSCOPED tail matches the tail of a `scoped_official` target
    but whose scope differs (including no-scope).
  - >
    Version-suffixed package — `react-18`, `webpack-5`, `python-3.12`.
    These are legitimate publisher-versioned aliases and must not be
    flagged. The rule treats numeric suffixes separated by `-` or `.`
    as non-material for the similarity comparison — the suffix is
    stripped before Damerau-Levenshtein evaluation.
  - >
    Deprecated-official official rename — `request` is deprecated in
    favour of `got`, yet `request` remains a published package and
    many legacy servers still depend on it. The rule must NOT flag
    `request` as a typosquat of `got` (distance-wise these are far
    apart anyway, but the rule nonetheless documents this class to
    acknowledge the failure mode).
  - >
    Author-internal name coinciding with a public near-miss — an org's
    private package `@acme/requestss` is three edits from public
    `requests`. The rule cannot distinguish private from public
    registries statically; it emits the finding with a
    `no_confirmed_malicious_record` factor (negative adjustment) so the
    reviewer sees that the finding is distance-only and can apply
    organisational context to dismiss.
  - >
    Short-name collisions — `axios` has length 5. A Damerau-Levenshtein
    distance of 2 against `axios` produces many legitimate 3-5 character
    unrelated names (e.g. a greenfield utility called `axles`). The
    rule uses the target's declared `max_distance` (2 for short names,
    3 for longer) and additionally requires a Jaro-Winkler similarity
    ≥ 0.80 before firing — agreement between two complementary
    algorithms is the filter against single-algorithm noise.

edge_case_strategies:
  - legitimate-fork-allowlist
  - visual-confusable-replay
  - scope-squat-detection
  - numeric-version-suffix-strip
  - algorithm-agreement-gate

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - target_distance_under_threshold
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Both npm and PyPI deploy registry-side homoglyph + Damerau-
    Levenshtein guards that reject submissions too close to existing
    popular names, AND lockfile generators refuse to record a resolved
    package whose name is within the supplier-enforced similarity
    radius. Under those conditions typosquats cannot reach a consumer's
    build environment in the first place, so the D3 detector becomes
    redundant.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# D3 — Typosquatting Risk in Dependencies

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Any MCP server whose dependency list has been collected
by the scanner — `context.dependencies`. npm and PyPI target cohorts
are covered out of the box.

## What an auditor accepts as evidence

A supply-chain auditor working to ISO 27001 A.5.21 will not accept a
finding that says "looks like a typosquat of lodash". They will accept
a finding that says:

1. **Similarity proof** — the finding cites a `Location` of
   `kind: "dependency"` with the observed name, the candidate target
   name, and the reproducible Damerau-Levenshtein distance. Optionally
   it records a Jaro-Winkler score above 0.80 confirming the lexical
   agreement across two algorithms. The auditor can recompute both
   metrics from the names alone.

2. **Classifier proof** — the finding enumerates which classifier
   pathway produced the match: (a) CONFIRMED-TYPOSQUAT registry hit,
   (b) SCOPE-SQUAT of a `scoped_official` target, (c) Damerau-
   Levenshtein under the target's declared ceiling, (d) visual-
   confusable grapheme match (rn/m, cl/d, vv/w), or (e) Unicode-
   confusable match. Each pathway is independently verifiable.

3. **Allowlist check** — the finding records whether the candidate is
   in `legitimate-forks.ts`. When it is, no finding is produced. The
   absence of a finding is itself audit evidence that the scanner
   examined and dismissed the candidate.

4. **Mitigation check** — the finding notes that package managers do
   not reject look-alike names at resolution time (the structural
   gap D3 exists to compensate for). Lockfiles pin a specific version
   but do not pin a spelling — a lockfile's presence does NOT
   invalidate a typosquat finding.

5. **Impact statement** — concrete description: malicious package
   executes during installation (postinstall hook) or at import time,
   yielding RCE in the build/server environment with the server's
   credentials — specifically material when the server is an MCP
   server that delegates tool authority to an agent.

## What the rule does NOT claim

- It does not claim the package is malicious. A finding is a lexical
  similarity signal paired with an absence of an allowlist record.
  The reviewer reads the npm/PyPI page for the candidate to decide
  intent.
- It does not check live registry state (download counts, publish
  dates, postinstall script presence). Those checks are owned by D5
  (known malicious packages) and by a future runtime-audit chunk.
- It does not resolve package rename redirects. If the registry has
  merged two names into one logical package the rule has no way of
  knowing without a network call.

## Why confidence is capped at 0.90

Similarity is inherently fuzzy. Even with algorithm agreement and
allowlist filtering, a static typosquat call can be wrong when:

- the dependency is a private internal fork legitimately named near
  a public target;
- the dependency is a well-known alias under a legacy namespace that
  was not captured in the legitimate-forks allowlist;
- the target's popularity threshold changed after the curated list
  was last updated.

Capping at 0.90 preserves explicit room for those externalities. The
remaining 0.10 signals: "strong static evidence, reviewer must confirm
identity against the public registry before removal."

## Relationship to D5 and D7

- D5 (Known Malicious Packages) emits confirmed-bad findings at
  confidence > 0.95 when the name is in a blocklist of published
  incidents.
- D7 (Dependency Confusion) flags scoped packages with artificially
  high version numbers (the 9999.x Birsan trick).
- D3 (this rule) fires on the full similarity surface including
  near-miss and scope-squat cases that D5/D7 do not cover.

All three are complementary; a finding from each on the same package
is expected and each cites different evidence.
