---
rule_id: P8
interface_version: v2
severity: high
owasp: MCP07-insecure-config
mitre: T1600
risk_domain: container-runtime

threat_refs:
  - kind: spec
    id: NIST-SP-800-38A
    url: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    summary: >
      NIST SP 800-38A explicitly states ECB mode is NOT recommended for
      confidentiality of multi-block plaintexts because identical
      plaintext blocks yield identical ciphertext blocks — the attacker
      learns equality relationships in the plaintext without breaking
      the cipher. This is the canonical reason "Tux the penguin in ECB"
      is the textbook illustration of broken crypto.
  - kind: spec
    id: OWASP-ASVS-6.2.3
    url: https://owasp.org/www-project-application-security-verification-standard/
    summary: >
      OWASP ASVS V6.2.3 requires authenticated encryption (AES-GCM,
      ChaCha20-Poly1305) and explicitly forbids ECB mode. Initialisation
      vectors MUST be generated from a CSPRNG and never reused under
      the same key. Math.random() and Python's random module are
      explicitly listed as unsuitable for cryptographic use.
  - kind: paper
    id: CWE-327
    url: https://cwe.mitre.org/data/definitions/327.html
    summary: >
      CWE-327 "Use of a Broken or Risky Cryptographic Algorithm" and
      CWE-329 "Generation of Predictable IV with CBC Mode" are the two
      weakness classes this rule detects. Both are CWE Top 25
      consistently since 2019 and are the root cause of every static-IV
      CTF challenge ever published.
  - kind: paper
    id: SlowMist-ECDSA-Nonce-Reuse
    url: https://slowmist.medium.com
    summary: >
      SlowMist's audit of web3 wallets documented multiple incidents
      where ECDSA nonce reuse enabled full private-key extraction from
      two signatures. The Math.random()-in-crypto variant of this rule
      is the exact same class of flaw — a non-CSPRNG producing two
      signatures with the same k recovers the private key in constant
      time. This rule fires on the pattern before the keys sign
      anything.

lethal_edge_cases:
  - >
    ECB mode smuggled via variable — `const mode = "aes-128-ecb";
    crypto.createCipheriv(mode, key, iv)`. A surface-level regex that
    greps for the literal string "aes-128-ecb" inside a createCipheriv
    call misses the indirection. The rule must follow variable bindings
    when the initializer is a string literal containing ECB.
  - >
    Static IV disguised as a random-looking buffer — `const iv =
    Buffer.alloc(16)` allocates a 16-byte zero buffer. A naive "is it
    Math.random()?" check passes; a "does the RHS name contain
    'random'?" check passes. The rule must recognise Buffer.alloc
    without a subsequent randomFill / crypto.randomBytes assignment as
    a zero IV (structurally equivalent to `iv = 0x000...0`).
  - >
    Math.random() inside a function whose NAME does not contain
    "encrypt" / "crypto" — but the function parameters or return value
    are used in a crypto call two frames away. A per-function linguistic
    classifier would miss this. The rule reduces false negatives by
    scanning the enclosing function body (not just the function name)
    for crypto-context tokens when deciding whether Math.random() is a
    crypto misuse.
  - >
    Authorised cryptographic test vectors — a fixture file contains
    `iv = Buffer.from("000000000000000000000000", "hex")` to verify
    GCM behaviour against a known test vector. The line is textbook
    static-IV. The rule MUST skip files structurally identified as
    tests (vitest/jest imports + describe blocks) rather than by
    filename — attacker could name a production file `.test.ts` and
    a filename heuristic would miss the rule.
  - >
    JWT algorithm confusion smuggled into HMAC verification — not P8's
    primary scope (that is C14) but the boundary is subtle: a file
    using HMAC-SHA256 with a 16-byte key derived from Math.random() is
    exactly the crypto-misuse this rule should fire on, AND is what
    C14 reviewers look at. The charter scopes P8 to primitive crypto
    constructions (cipher mode + IV + PRNG); JWT algo choice stays
    with C14.

edge_case_strategies:
  - variable-resolved-ecb-mode
  - buffer-alloc-as-zero-iv
  - enclosing-scope-crypto-context
  - structural-test-skip
  - c14-boundary-respect

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - crypto_misuse_pattern
    - csprng_available_nearby
    - crypto_variant
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Node.js's crypto module and Python's ssl / cryptography default to
    refusing ECB creation and to allocating random IVs automatically,
    AND JavaScript removes `Math.random()` in favour of a CSPRNG-backed
    primitive — at which point static detection of these patterns is
    belt-and-braces.
---

# P8 — Insecure Cryptographic Mode or Static IV/Nonce

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** TypeScript / JavaScript source code that performs
cryptographic operations, either directly via the `crypto` / `node:crypto`
module or through thin wrapper libraries.

## What an auditor accepts as evidence

A NIST SP 800-38A / OWASP ASVS V6.2.3 auditor will not accept "file
contains the string ECB" as evidence. They will accept:

1. **Scope proof** — the finding names a specific AST construct:
   either a string literal passed to `crypto.createCipher*` naming an
   ECB mode, a variable declaration whose name is `iv` / `nonce` /
   `salt` initialised to a constant, or a `Math.random()` call whose
   enclosing function body contains crypto-context tokens.

2. **Gap proof** — the finding identifies which variant fired
   (`ecb_mode`, `static_iv`, `math_random_crypto`). The auditor can
   correlate to the specific CWE class (327 for ECB, 329 for static
   IV, 338 for Math.random in crypto).

3. **Mitigation check** — the rule reports whether a CSPRNG
   (`crypto.randomBytes`, `crypto.getRandomValues`, `randomUUID`,
   `randomFillSync`, WebCrypto) is imported or used elsewhere in the
   same file. Presence does NOT suppress the finding — the mitigation
   proves the author *knows* about the CSPRNG but chose a weaker
   primitive at this call site, which is arguably worse than ignorance.

4. **Impact statement** — the cipher-specific consequence:
   ECB leaks plaintext equality patterns; static IVs enable two-time-
   pad attacks on stream ciphers and known-plaintext attacks on CBC;
   Math.random()-derived nonces allow ECDSA private-key extraction
   from two signatures (SlowMist web3 incidents, 2022–2024).

## What the rule does NOT claim

- It does not decrypt or attack the actual ciphertext — static
  detection of a broken primitive is evidence of RISK, not evidence
  of active compromise.
- It does not cover JWT algorithm confusion (C14 owns that boundary).
- It does not scan config files for "USE_ECB=1" env variables — that
  is runtime posture, not a primitive misuse.

## Why confidence is capped at 0.80

Static detection of a cipher mode / IV generator / PRNG call is
unambiguous. The 0.80 cap leaves room for two uncertainty sources:
(a) the code path might be unreachable in production (dead code),
(b) the crypto material might be immediately rewritten by a
downstream wrapper (e.g. `iv = crypto.randomBytes(16)` one line after
the Buffer.alloc declaration). A per-binding reachability analysis
could raise this cap in Phase 2; today, 0.80 is honest.
