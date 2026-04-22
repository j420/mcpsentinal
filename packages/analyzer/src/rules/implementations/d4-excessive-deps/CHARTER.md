---
rule_id: D4
interface_version: v2
severity: low

threat_refs:
  - kind: spec
    id: SLSA-Supply-Chain-Levels
    url: https://slsa.dev/spec/v1.0/
    summary: >
      Supply-chain Levels for Software Artifacts (SLSA) v1.0 articulates
      the dependency blast-radius problem explicitly: as the direct and
      transitive dependency count grows, the probability of at least one
      compromised dependency tends to 1. SLSA controls (provenance,
      isolated builds, hermetic sources) scale linearly with dependency
      count; projects that exceed the practical SLSA-2 monitoring
      threshold without tooling are ambient-risk.
  - kind: paper
    id: Dependency-Blast-Radius-2022
    url: https://arxiv.org/abs/2207.01727
    summary: >
      Zimmermann et al. "Small World with High Risks: A Study of
      Security Threats in the npm Ecosystem" (USENIX 2019 / arXiv 2207
      follow-ups). Empirical finding: the median top-level npm package
      pulls in >75 transitive dependencies, and a single compromise of
      any of them compromises every downstream consumer. Quantifies the
      risk D4 surfaces.
  - kind: spec
    id: OWASP-MCP08-Dependency-Vulnerabilities
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP08 — Dependency Vulnerabilities. Identifies
      "unnecessary or bloated dependency sets" as a primary risk
      multiplier; D4 is the automated proxy for this control.
  - kind: spec
    id: ISO-27001-A.8.25
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.25 — Secure Development
      Lifecycle. Requires minimisation of the software attack surface
      by including only components required for the application's
      function. A dependency count far above the organisational baseline
      is a documented exception under A.8.25.

lethal_edge_cases:
  - >
    Legitimately-dependency-rich packages. React/Next.js-based MCP
    servers, VSCode-extension-style tools, and frameworks that build
    on Babel+ESLint+Prettier easily have >50 direct deps — this is
    normal rather than anomalous. The rule treats >50 as a SIGNAL to
    investigate, not an assertion of bloat. Evidence chain frames the
    finding as "attack surface above the policy threshold" and notes
    the threshold itself so the reviewer can argue for a project-local
    exception.
  - >
    Transitive-heavy trees with few direct deps. A project with 15
    direct deps but 800 transitives has a larger real attack surface
    than one with 55 direct and 200 transitives. D4 intentionally
    measures direct deps only — the DependencyAuditor populates
    context.dependencies with the union, and D4 treats the size of
    that union as the measurable surface. This is a coarse signal;
    deeper transitive-graph audit is tracked as Layer 5 follow-up.
  - >
    Monorepo false positives. A monorepo's top-level manifest lists
    every workspace's deps, trivially exceeding any threshold. The
    scanner is not monorepo-aware in 2026.Q1 and will flag the
    top-level manifest. The reviewer dismisses this by checking the
    pnpm-workspace.yaml / lerna.json / turbo.json presence — D4's
    chain documents this explicitly so the dismissal is audit-trailed.
  - >
    Extremely large count (>200). At this scale the finding switches
    from "review the manifest" to "the project is unauditable". The
    rule records the count verbatim and elevates the factor weight so
    downstream severity policy can tier automatically (e.g. treat >200
    as medium, 50-200 as low, <50 as no-finding).

edge_case_strategies:
  - count-exact-passthrough
  - tiered-factor-weight
  - monorepo-reviewer-note

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - dependency_count_over_threshold
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Organisation-specific SBOM policy tooling ingests dependency counts
    and makes context-aware decisions (framework-aware thresholds,
    monorepo-awareness). D4 then degrades to a "policy tripwire" that
    is trivially replaced by policy-as-code.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# D4 — Excessive Dependency Count

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any project with a populated `context.dependencies` array.
Threshold: 50 direct deps (retained from legacy v1 for continuity).

## Relationship to DependencyAnalyzer engine

The engine's D4 branch emits a legacy finding. Once this v2 rule is
registered the engine dispatcher defers to it and this rule is the
canonical producer.

## Why low severity

Dependency count is a signal, not a vulnerability. A project with 60
well-curated dependencies is safer than one with 10 abandoned ones.
Severity is intentionally low so D4 serves as a tripwire for deeper
investigation — not an urgent finding.

## Confidence cap: 0.60

Policy-dependent. Reviewers should raise or lower it by organisational
baseline.
