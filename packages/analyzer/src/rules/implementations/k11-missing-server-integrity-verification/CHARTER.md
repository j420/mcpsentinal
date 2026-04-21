---
rule_id: K11
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: CoSAI-MCP-T6
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Coalition for Secure AI MCP threat taxonomy T6 — Supply Chain Integrity.
      Requires cryptographic verification (checksum, signature, registry
      attestation) of every MCP component loaded at runtime. A server that
      pulls a package at boot without integrity proof violates T6 by
      construction: the downloaded artefact might have been replaced between
      the last audit and the current invocation.
  - kind: spec
    id: CoSAI-MCP-T11
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP threat category T11 — Supply Chain / Lifecycle Failures.
      Dynamic loaders (require, importlib.import_module, wget + shell exec,
      npm install at runtime) that bypass the build-time lockfile are a
      primary T11 failure pattern. Even a correct lockfile does not help if
      the server fetches and runs a fresh payload on every start.
  - kind: spec
    id: ISO-27001-A.8.24
    url: https://www.iso.org/standard/82875.html
    summary: >
      ISO/IEC 27001:2022 Annex A 8.24 — Use of cryptography. Cryptographic
      controls (integrity hashes, digital signatures, subresource
      integrity) must be applied to protect assets. Dynamic code loaded
      without such controls is an auditable control gap.
  - kind: spec
    id: MAESTRO-L3
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 3 (Agent Frameworks) treats the tool marketplace /
      plugin loader as an adversary-controlled surface. Every loaded
      tool that arrives without integrity evidence is treated as
      hostile until proven otherwise.
  - kind: paper
    id: Birsan-Dependency-Confusion-2021
    url: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610
    summary: >
      Alex Birsan 2021 disclosure — private-package name squatted on the
      public registry, installed by affected companies within hours.
      Demonstrates why "the registry gave it to me" is not integrity
      evidence — the registry boundary is an attacker-controlled surface
      in the absence of a package-level signature / hash check.

lethal_edge_cases:
  - >
    Dynamic import as data — `await import(userConfig.serverPath)` reads
    the specifier from a runtime value. A plain CallExpression-by-name
    check (looking for `require("...")`) misses it; the rule must detect
    `ts.SyntaxKind.ImportKeyword` CallExpressions separately and still
    check the enclosing scope for integrity calls.
  - >
    Integrity verification call lives outside the enclosing function —
    a caller validates the checksum once at process boot, then reuses a
    handle for subsequent loads. A narrow "same function body" check
    would false-positive on every subsequent load. The rule walks the
    lexical ancestor chain up to the file scope and tolerates hashes
    verified at file-scope top-level for the same bound identifier.
  - >
    Shelling out to fetch — `exec("curl -s URL | node")` or
    `spawnSync("sh", ["-c", "wget ... && bash -c"])`. A detector that
    only walks JS CallExpressions misses the subprocess boundary. The
    rule classifies subprocess invocations whose argv tokens contain
    network-fetch vocabulary (curl, wget, fetch, http_get) followed by
    evaluator vocabulary (sh, bash, node, eval) as an integrity-free
    load and flags them.
  - >
    Vendored checksum in a separate config file — the loader reads a
    `integrity.json` sibling file and compares. The enclosing function
    scope only contains a `readFileSync("integrity.json")` call with
    no `createHash` locally. The rule recognises filename-shaped
    string literals containing integrity / checksum / manifest /
    sha256 / sha512 / sri as an integrity-bearing reference and
    treats the call as guarded.
  - >
    Test harness dynamically imports fixtures — a vitest suite calls
    `await import(fixturePath)` thousands of times without any
    integrity check. Firing on these obliterates signal. The rule
    performs a structural test-file detection (vitest/jest/mocha
    imports + describe/it/test at top level) and skips the file
    wholesale; filename-based skipping is explicitly avoided per
    K1's "test-file camouflage" lesson.

edge_case_strategies:
  - import-keyword-ast              # dynamic import() detected as a distinct CallExpression kind
  - ancestor-scope-integrity-walk   # walk ancestor chain up to file scope looking for integrity calls
  - subprocess-fetch-exec-chain     # argv classification for shell-mediated fetch+execute patterns
  - integrity-filename-literal      # string literals referencing integrity/checksum config files count
  - structural-test-file-detection  # skip test files via AST shape, not filename

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - dynamic_loader_kind
    - no_integrity_in_scope
  location_kinds:
    - source

obsolescence:
  retire_when: >
    MCP specification mandates signed component manifests (signature
    algorithm, public-key fingerprint, and revocation list) enforced
    by the protocol layer — at which point integrity verification
    becomes a protocol invariant and a static rule that names the
    gap no longer has work to do.
---

# K11 — Missing Server Integrity Verification

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers (TypeScript/JavaScript) that load external
code, binaries, or server components at runtime.

## What an auditor accepts as evidence

An ISO 27001 A.8.24 auditor will not accept a rule that says "we did
not find a checksum". They will accept a rule that:

1. Names the specific **loader call** — a concrete `ts.CallExpression`
   or `ts.NewExpression` with a structured `source`-kind Location —
   and names the loader's class (`require-call`, `dynamic-import`,
   `mcp-server-ctor`, `spawn-curl-exec`, `install-at-runtime`).

2. Walks the **ancestor chain** from that call to the file scope and
   reports whether ANY integrity-verifying call (`createHash`,
   `verifyIntegrity`, SRI token, signature verification library) OR
   ANY integrity-bearing filename literal was observed.

3. Reports the **mitigation** link explicitly — present (hash call
   observed upstream) or absent (no integrity evidence within the
   walked scopes). The mitigation is as important as the sink: a
   future PR that adds a hash check flips the finding to "present"
   without rewriting the rule.

4. States the **impact** in concrete supply-chain terms — an
   attacker who controls the source (typosquat, hijacked registry,
   MITM) gets arbitrary code execution in the server's process
   space, which in the MCP architecture is the agent's trust zone.

## Confidence cap — 0.88

Dynamic loader configuration can live at boot time (process arguments,
mounted secrets, environment-specified allowlists) that static analysis
does not see. A maximum-confidence claim would overstate what the
analyzer can prove from file scope alone.
