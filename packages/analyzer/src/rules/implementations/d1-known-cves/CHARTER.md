---
rule_id: D1
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2019-10744
    summary: >
      lodash defaultsDeep prototype pollution RCE. Used in D1 as the
      archetypal "well-known CVE in a ubiquitous transitive dependency"
      — the class of finding the rule exists to surface.
  - kind: cve
    id: CVE-2022-21449
    summary: >
      Java ECDSA 'Psychic Signatures'. Illustrates that a patched CVE
      in a widely-used library is only a fix if the installed version
      is above the patch floor; a pinned old version with a listed CVE
      remains exploitable until the consumer upgrades.
  - kind: cve
    id: CVE-2025-30066
    summary: >
      tj-actions/changed-files GitHub Action tag poisoning with
      workflow-log secret exfiltration. Demonstrates that a CVE-flagged
      version must be treated as compromised even when the CI pipeline
      pins the affected tag — the D1 rule's evidence must point at the
      exact version string for auditor reproduction.
  - kind: spec
    id: OWASP-MCP08-Dependency-Vulnerabilities
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP08 — Dependency Vulnerabilities. Explicitly
      requires scanning for known-CVE dependencies and refusing to
      deploy affected versions.
  - kind: spec
    id: ISO-27001-A.8.8
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 8.8 — Management of Technical
      Vulnerabilities. Requires timely identification of vulnerabilities
      in technical assets and evaluation of exposure. Dependency CVE
      detection is the primary automated control that operationalises
      A.8.8 for software-bill-of-materials.

lethal_edge_cases:
  - >
    Stale CVE list at scan time. The scanner's OSV/NVD mirror can trail
    the public advisory by minutes or hours. A clean D1 result at T0
    does not warrant a "no known CVEs" claim at T0+24h. The finding
    documents the exact last_updated timestamp of the audit source so
    the auditor can recompute against a fresher snapshot. When the
    dependency's `cve_ids` array is empty the rule does NOT fire even
    if `has_known_cve=true` — we never guess a CVE id.
  - >
    Git-URL pinned dependency. `"foo": "git+https://github.com/acme/foo.git#sha"`
    is a real installed dependency but the scanner cannot resolve the
    exact released version from the manifest alone. The rule silently
    skips such entries (version=null); the auditor sees a coverage gap
    rather than a misleading green. This keeps the D1 chain from
    asserting a version string the manifest doesn't contain.
  - >
    Transitive-only vulnerability. The direct dependency is clean but a
    transitive nested in its tree is affected. The AnalysisContext's
    `dependencies` array is populated from the manifest (direct deps)
    AND the lockfile audit (transitives). The rule treats both alike —
    the evidence Location (kind: dependency) records the ecosystem and
    name so the reviewer can follow the resolution chain back to the
    manifest entry that pulled it in, without the rule needing to walk
    the dep tree itself.
  - >
    Multi-CVE dependency. A single package may be affected by 3+ CVEs
    of varying severity. The rule emits ONE finding per dependency
    (never one per CVE) — noise control. All CVE ids are recorded in
    the chain's sink.observed and in the finding metadata. The first
    CVE id is elevated to cve_precedent so the impact narrative ties
    to a concrete advisory.
  - >
    Advisory withdrawn / rejected. NVD occasionally rejects a CVE as
    duplicate or erroneous. The auditor data source is ultimately
    authoritative; if the scanner's `cve_ids` still contains a rejected
    id, the rule fires anyway — false positive is preferable to false
    negative and the rationale chain shows exactly which id and link
    to double-check.

edge_case_strategies:
  - empty-cve-array-skip
  - version-null-silent-skip
  - single-finding-per-dep
  - cve-id-manifest-passthrough

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - known_cve_presence
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Package registries enforce registry-side CVE blocking at publish
    AND resolve time, AND lockfile generators refuse to materialise a
    dependency with an unpatched advisory. Under those conditions the
    D1 detector becomes redundant because an affected version can no
    longer reach a consumer's build environment.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# D1 — Known CVEs in Dependencies

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any MCP server whose dependency list has been populated by
the scanner's DependencyAuditor (`context.dependencies[*].has_known_cve`).
Covers npm and PyPI ecosystems out of the box; any ecosystem the auditor
populates is routed identically.

## Relationship to DependencyAnalyzer engine

Stage 3 `DependencyAnalyzer` (`packages/analyzer/src/engines/dependency-analyzer.ts`)
historically produced a flat D1 finding without an evidence chain. The engine
dispatcher in `engine.ts` defers the engine finding to the TypedRule
implementation when the YAML rule is `detect.type: typed` AND a TypedRule
is registered. This v2 rule is the authoritative D1 producer; the engine's
D1 branch remains as a safety net for future non-TypedRule-using pipelines.

## What an auditor accepts as evidence

An auditor operating under ISO 27001 A.8.8 / A.5.21 requires:

1. **Dependency identity** — ecosystem, package name, exact installed version,
   recorded as a structured `dependency` Location.
2. **CVE list** — every CVE id from the auditor output, with the first id
   elevated to `sink.cve_precedent` for the narrative.
3. **Manifest pointer** — RFC 6901 JSON pointer into `package.json` /
   `pyproject.toml` so the auditor can reproduce the finding from the
   manifest alone.
4. **Mitigation check** — explicit "no patched version installed" mitigation
   recorded with `present: false`.
5. **Impact statement** — the class of exploitation associated with the CVE
   family (typically RCE or privilege escalation).

## Confidence cap: 0.92

High confidence — OSV/NVD are authoritative. The 0.08 gap accounts for:
- the CVE list being a point-in-time snapshot;
- the occasional rejected/withdrawn advisory;
- the possibility that a fix is backported via patch-package that the
  static analysis cannot see.
