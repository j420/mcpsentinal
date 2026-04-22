---
rule_id: D6
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CWE-327
    url: https://cwe.mitre.org/data/definitions/327.html
    summary: >
      CWE-327: Use of a Broken or Risky Cryptographic Algorithm. The
      canonical control that D6 operationalises for dependency-level
      cryptography. A project that imports a library whose primary
      crypto primitive is broken (MD5, SHA-1, RC4, DES) is inheriting
      the CWE-327 finding by transit even if the application code
      never calls the primitive directly — a future contributor will.
  - kind: paper
    id: SHAttered-2017
    url: https://shattered.io/
    summary: >
      Stevens, Bursztein, Karpman, Albertini, Markov "The First
      Collision for Full SHA-1" (CRYPTO 2017). Demonstrated a
      practical collision for SHA-1 in ~110 GPU-years. Libraries that
      ship SHA-1 as their primary primitive must be considered
      broken-by-default for any signature/integrity use.
  - kind: cve
    id: CVE-2022-21449
    summary: >
      Java ECDSA 'Psychic Signatures' — JWT signature bypass via
      all-zero (r,s). Cited here because `jsonwebtoken` below 8.5.1
      accepts algorithm downgrades at verify time; the D6 blocklist
      calls this out specifically because weak-crypto-dep is how the
      CVE reaches production MCP servers.
  - kind: spec
    id: FIPS-140-3
    url: https://csrc.nist.gov/pubs/fips/140-3/final
    summary: >
      FIPS 140-3 enumerates the approved cryptographic algorithm set
      for US federal systems. MD5, SHA-1 (for signatures), DES, and
      RC4 are explicitly disapproved. D6's blocklist is the automated
      detection path for a FIPS-compliant SBOM — a package whose name
      matches a D6 entry cannot ship in a FIPS-scoped system.
  - kind: spec
    id: OWASP-MCP07-Insecure-Configuration
    url: https://owasp.org/www-project-top-10-for-large-language-model-applications/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. Weak-crypto
      library imports are a primary configuration-level
      vulnerability.

lethal_edge_cases:
  - >
    Package is fine; its default API is broken. `node-forge` and
    `crypto-js` both include MD5 and SHA-1 as exported utilities but
    also expose modern primitives. Simply importing the library is
    not itself a finding IF the caller pins a safe version AND uses
    the safe primitives. D6 addresses the first half (version pin)
    with a semver gate; the second half (API usage) is covered by
    C-rules (source-level crypto inspection), not D6.
  - >
    Semver range vs exact version. A manifest entry "crypto-js": "^3.1.0"
    will resolve at install time to whatever ^3 tip exists. D6 inspects
    the installed version (context.dependencies[*].version), not the
    manifest semver range. This is correct: the RESOLVED version is the
    running version.
  - >
    pycryptodome vs pycrypto. The abandoned `pycrypto` was superseded
    by `pycryptodome` (API-compatible fork). Projects still importing
    `pycrypto` are exposed to CVE-2013-7459 and unpatched future
    CVEs; projects importing `pycryptodome` are fine. D6's blocklist
    distinguishes these precisely — a false positive here would be
    catastrophic for Python MCP servers.
  - >
    jsonwebtoken algorithm-confusion overlap with C14. `jsonwebtoken`
    pre-8.5.1 accepts 'none' algorithm and RS256→HS256 downgrade.
    C14 (JWT Algorithm Confusion) detects the SOURCE-level usage
    pattern; D6 detects the DEPENDENCY-level version pin. Both fire
    when a pre-8.5.1 project uses the library unsafely — that is the
    correct belt-and-braces coverage for the same CVE class.
  - >
    bcrypt-nodejs vs bcrypt vs bcryptjs. Three packages; only
    bcrypt-nodejs is problematic (unmaintained, weak entropy in salts).
    The blocklist calls out the bad one explicitly; D6 does NOT flag
    the good ones on name-family heuristics.

edge_case_strategies:
  - exact-name-semver-gated
  - modern-fork-explicit-allowlist
  - c14-overlap-acknowledged

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - weak_crypto_package_hit
  location_kinds:
    - dependency
    - config

obsolescence:
  retire_when: >
    Node and Python stdlib remove MD5/SHA-1 as default exports AND
    every major framework defaults to modern crypto primitives; AND
    the package registries automatically block publishes that
    re-export the deprecated primitives. Under those conditions the
    static-dep-level D6 detector becomes redundant.
---

# D6 — Weak Cryptography Dependencies

**Author:** Senior MCP Supply-Chain Researcher + Senior MCP Security Engineer.
**Applies to:** Any dependency in `context.dependencies`.

## Semver comparison strategy

The rule uses a minimal hand-rolled semver comparator (see `data/semver.ts`).
It supports x.y.z and x.y.z-prerelease. No regex. The scan data is always
a resolved version from the auditor, so loose range parsing is out of scope.

## Relationship to C14 (JWT Algorithm Confusion)

C14 detects `jsonwebtoken.verify(..., { algorithms: ['none'] })` at the
SOURCE level. D6 detects `"jsonwebtoken": "<8.5.1"` at the DEPENDENCY level.
Both fire in the canonical unsafe case. Complementary, not redundant.

## Confidence cap: 0.88

Authoritative but one rung below D5 (exact malicious-package hit). The
0.12 head-room accounts for:
- the semver gate potentially missing an odd-shaped version string;
- the caller importing the library but never calling the weak primitives;
- rare compatibility needs (legacy system interop).

## FIPS 140-3 mapping

D6 output is direct SOC 2 / FIPS 140-3 audit evidence. The advisory url
field on every entry is the citation an auditor uses to close the control.
