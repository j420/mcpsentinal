---
rule_id: K10
interface_version: v2
severity: high

threat_refs:
  - kind: incident
    id: Birsan-Dependency-Confusion-2021
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Alex Birsan's February 2021 dependency-confusion research.
      Birsan demonstrated remote-code execution against Apple,
      Microsoft, PayPal, Shopify, Netflix, and 30+ other companies
      by publishing packages to the PUBLIC npm / PyPI registries
      whose names matched unpublished INTERNAL packages. The direct
      control via registry URLs (npmrc / pip.conf) is K10's primary
      target: an attacker who controls the configured registry URL
      serves ANY package with ANY contents, not just typosquats.
  - kind: spec
    id: ISO-27001-A.5.21
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A Control 5.21 — Managing information
      security in the ICT supply chain. Requires organisations to
      identify, document, and control the sources of their
      information-processing components. An unconstrained registry
      URL in .npmrc / pip.conf / go.env violates this control by
      accepting unidentified upstream sources.
  - kind: spec
    id: CWE-829
    url: https://cwe.mitre.org/data/definitions/829.html
    summary: >
      CWE-829 — Inclusion of Functionality from Untrusted Control
      Sphere. The registry URL IS the control sphere. Any code
      served from it is included in the application; if the sphere
      is not trusted, the inclusion is the weakness.
  - kind: paper
    id: CoSAI-MCP-T6-Missing-Integrity-Verification
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP Security threat taxonomy, T6 — Missing Integrity
      Verification. Explicit about package-registry substitution as
      a threat vector for MCP servers; the coalition's guidance
      recommends registry pinning with integrity hashes (npm's
      integrity field, pip's --require-hashes) as the primary
      mitigation.

lethal_edge_cases:
  - >
    Enterprise mirror camouflage — the URL
    https://artifactory.corp-looking.com/npm/ is not in the official
    trusted list but is equally not obviously malicious. A naive
    allowlist check treats it the same as https://evil.com/npm/.
    The rule must distinguish truly untrusted (unknown public host)
    from enterprise-shaped (artifactory/nexus/verdaccio/jfrog
    substring in hostname) and reserve the high-severity finding for
    the first class. Enterprise-shaped mirrors get a lower-severity
    informational advisory about missing integrity hashes.
  - >
    Scoped registry escape — .npmrc contains
    `@mycompany:registry=https://corp.com/npm/` AND the global
    `registry=https://evil.com/npm/`. The scoped line is benign
    (only @mycompany packages come from the corp mirror); the
    global line substitutes EVERY other package. A rule that only
    looks at the first registry= line misses the global override.
    K10 must check EVERY registry= assignment, not just the first.
  - >
    Protocol-downgrade variant — registry=http://registry.npmjs.org/
    (note: http, not https). The hostname is trusted but the
    transport is not. An on-path attacker can inject any package
    content. A trusted-hostname check alone misses this; the rule
    must also verify the URL uses https.
  - >
    GOPROXY with a comma list — GOPROXY=https://proxy.golang.org,
    direct,https://evil.corp/modcache. Multiple proxies are a
    feature (fallback chain), but any untrusted entry in the chain
    is the substitution primitive. The rule must split on comma and
    check every proxy.
  - >
    Runtime injection via env var — the configuration is not in a
    file; the CI pipeline exports NPM_CONFIG_REGISTRY=... or sets
    it via `npm config set registry`. A static scan of .npmrc
    misses this. K10's fallback must scan source code for the
    environment-variable primitive (export NPM_CONFIG_REGISTRY,
    `npm config set registry`, process.env.NPM_CONFIG_REGISTRY
    assignments) and flag any non-trusted URL written there.

edge_case_strategies:
  - enterprise-vs-untrusted-classification
  - scoped-registry-exception-handling
  - protocol-https-enforcement
  - goproxy-comma-list-split
  - runtime-env-var-injection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - registry_url_classified
    - trust_comparison
    - integrity_hash_mitigation
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    The major package managers (npm, yarn, pnpm, pip, uv, go modules)
    refuse any registry URL that is not a signed, enumerated member
    of a published trust anchor list, AND enforce cryptographic
    package-signature verification by default. Until both hold,
    unconstrained registry URLs remain the simplest way to MITM every
    install in a fleet.

mutations_survived: []
mutations_acknowledged_blind: []
---

# K10 — Package Registry Substitution

**Author:** Senior MCP Threat Researcher.
**Applies to:** .npmrc / pip.conf / pyproject.toml / go.env / yarn.lock
configuration files AND source code that sets these values via
environment variables or API calls.

## What an auditor accepts as evidence

1. **Registry URL classification** — the finding names the specific
   URL and classifies it: (a) a known official registry
   (registry.npmjs.org, pypi.org, proxy.golang.org, …) — NO finding;
   (b) a localhost / private-network / enterprise-shaped mirror
   (Artifactory / Nexus / Verdaccio / JFrog hostname substring) —
   informational advisory, not a high-severity finding; (c) anything
   else — the K10 finding fires.

2. **Trust comparison** — the evidence explicitly shows WHICH trusted
   registry for that ecosystem this URL replaces. A .npmrc pointing
   at `https://mirror.evil.com/` replaces
   `https://registry.npmjs.org/`. The comparison is what makes the
   finding actionable: the reviewer sees exactly what trust relationship
   has been broken.

3. **Integrity mitigation check** — the rule reports whether the
   package manager is configured to REQUIRE integrity hashes
   (package-lock.json with integrity fields, `pip install
   --require-hashes`, go.sum present). Integrity enforcement reduces
   (but does not eliminate) the risk because an attacker with
   first-serve access to the registry can still serve a backdoored
   package the first time; hash pinning prevents them from swapping
   versions later.

4. **Impact statement** — Birsan (2021) demonstrated the end-to-end
   primitive: a registry URL the attacker controls serves any
   package; every dependency install becomes remote code execution.

## Differences from K11 and D5

- **K11** (Missing Server Integrity Verification) is the positive
  form: "is integrity configured?". K10 is the negative form: "is
  the registry URL even trusted?". K11 mitigates K10 when present.
- **D5** (Known Malicious Packages) names specific bad package
  names (@mcp/sdk typosquat etc.). K10 does not enumerate packages;
  it flags the UPSTREAM.

## Why confidence is capped at 0.80

Enterprise registries exist and are common (Artifactory, Nexus,
Verdaccio, JFrog are legitimate supply-chain tooling). The rule
uses a substring heuristic to distinguish enterprise-shaped from
truly-unknown mirrors, but the heuristic is not perfect: a cloud-
managed enterprise mirror at `pkg.internal.corp-looking.com` may
be legitimate even though no substring matches. 0.80 reserves
confidence for reviewer judgement on edge cases.
