---
rule_id: L5
interface_version: v2
severity: high

threat_refs:
  - kind: paper
    id: Clarke-npm-Manifest-Confusion-2023
    url: https://blog.vlt.sh/blog/the-massive-hole-in-the-npm-ecosystem
    summary: >
      Darcy Clarke (former npm CLI lead) disclosed in July 2023 that npm
      permits the REGISTRY manifest (the package.json served by npmjs.com
      and consumed by audit tools) to diverge arbitrarily from the
      TARBALL manifest actually installed onto the victim's machine. A
      publisher can add malicious postinstall scripts, switch the bin
      entry, or inject extra dependencies between the two views. Still
      unpatched as of April 2026.
  - kind: paper
    id: JFrog-Manifest-Confusion-Six-Months-Later-2024
    url: https://jfrog.com/blog/npm-manifest-confusion-six-months-later/
    summary: >
      JFrog's March 2024 follow-up identified 800+ packages on npm whose
      registry metadata and tarball contents disagree. The research
      confirmed that the disagreement classes most likely to hide
      malicious behaviour are (a) prepublish scripts that rewrite the
      tarball package.json in-place, and (b) bin field entries that
      shadow system commands or point at hidden-file payloads.
  - kind: paper
    id: Socket-exports-map-abuse-2025
    url: https://socket.dev/blog/exports-map-abuse-in-npm-packages
    summary: >
      Socket.dev 2025 research on "exports map abuse" — how divergent
      import/require conditional-export paths let an attacker ship a
      clean module to auditors (who examine the import path with
      vitest/esbuild) while consumers using require receive a
      backdoored file. Concretely observed in live npm typosquats in
      2024-2025.
  - kind: spec
    id: CWE-345
    url: https://cwe.mitre.org/data/definitions/345.html
    summary: >
      CWE-345 — Insufficient Verification of Data Authenticity. The
      absence of cryptographic binding between the published package
      manifest and the installed tarball manifest maps directly to this
      weakness; every L5 finding is an instance of it.

lethal_edge_cases:
  - >
    Prepublish script that mutates package.json in place — the script
    says `tsc` (legitimate) AND `sed -i s/.../.../ package.json` in the
    same && chain. A keyword-only check that greps for "tsc" would mark
    the command as benign build tooling; the rule must decompose the
    script and detect ANY mutation-of-manifest primitive regardless of
    what else the same chain runs.
  - >
    Bin entry shadowing a system command with a legitimate-looking
    auxiliary suffix: { "bin": { "git": "./bin/git-helper.js" } }. A
    human reviewer might read this as "a helper for git"; when
    installed globally npm silently symlinks node_modules/.bin/git over
    the real /usr/bin/git. The rule must flag ANY bin key whose name
    exactly matches a common system command, even if the target path
    looks innocuous.
  - >
    Bin entry pointing at a dot-prefixed or __-prefixed file path: { "bin":
    { "mcp-server": "./.hidden-payload.js" } }. Directory listings (ls,
    npm pack manifests, reviewer tarball extractions) hide dot-files by
    default, so the actual code path is invisible in normal audits. The
    rule flags any bin target whose filename component starts with "."
    or "__" regardless of how the name column looks.
  - >
    Divergent conditional exports with a suspicious filename in one
    branch: exports["."] = { import: "./esm/index.js", require:
    "./cjs/.payload.cjs" }. The ESM path is what esbuild / vitest / npm
    pack --dry-run show reviewers; the CJS path is what legacy
    consumers (and most auto-bundlers in 2026) actually load. The rule
    must flag divergence where at least one path contains a payload-
    shaped filename (backdoor, payload, hook, inject, hidden,
    .dotprefix).
  - >
    Exports map blocks ./package.json — setting
    `exports["./package.json"] = null` prevents audit tools (npm
    outdated, dependency-cruiser, socket-cli) from reading the
    installed manifest at runtime. This is NOT a primitive on its own,
    but it is a strong amplifier: it guarantees that manifest-confusion
    primitives elsewhere in the file stay undetected post-install.

edge_case_strategies:
  - prepublish-manifest-mutation
  - bin-field-system-command-shadow
  - bin-field-hidden-target
  - exports-conditional-divergence
  - exports-package-json-block

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - manifest_shape_confirmed
    - primitive_classified
    - publisher_integrity_gap
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    npm (and the downstream yarn/pnpm) adopt a cryptographic binding
    between the registry-served package.json and the tarball
    package.json (e.g. Sigstore provenance covering the manifest itself,
    not just the tarball digest) — AND the major MCP clients refuse to
    install packages whose two manifest views do not match. Until both
    conditions hold, L5 stays in the ruleset because the attack surface
    is structurally unfixed.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# L5 — Package Manifest Confusion

**Author:** Senior MCP Threat Researcher.
**Applies to:** MCP server source code and package.json manifests that
define prepublish / prepublishOnly scripts, bin entries, or exports
maps.

## What an auditor accepts as evidence

A supply-chain auditor evaluating an L5 finding wants to see four
things before they will act on it:

1. **Manifest shape proof** — the finding points at an object literal
   (or a parsed package.json) whose structure matches the npm manifest
   contract: it has a `scripts`, `bin`, or `exports` field whose value
   is well-formed for that field. A plain object that happens to have
   a `bin` key is not enough; the rule confirms the enclosing shape.

2. **Primitive classification** — the evidence names WHICH L5 primitive
   fired:
   - `prepublish-manifest-mutation` — a prepublish / prepublishOnly
     script rewrites package.json (sed, jq, node -e, mv, cat > …) and
     is NOT paired with a build-only invocation (tsc, esbuild,
     rollup, webpack);
   - `bin-system-shadow` — a bin key exactly matches a common system
     command (ls, cat, git, curl, node, npm, python, ssh, sudo …);
   - `bin-hidden-target` — a bin target path's file component starts
     with `.` or `__`;
   - `exports-divergence` — `exports["."]` has non-equal import and
     require targets AND at least one of them contains a payload-
     shaped filename substring;
   - `exports-package-json-block` — `exports["./package.json"]` is
     null or false, blocking audit-tool access to the installed
     manifest.

3. **Mitigation check** — the rule reports whether the package uses
   `npm publish --provenance` (Sigstore attestation), whether
   `publishConfig.provenance: true` is set, whether the repo has a
   .npmignore file at all, and whether a lockfile with integrity
   hashes is committed. All four absent is a strong amplifier; any
   present reduces confidence.

4. **Impact statement** — CWE-345 framing: the registry manifest can
   diverge from the installed tarball at publish time, and the
   specific primitive flagged would be invisible to every reviewer
   who checked the registry-served manifest before install.

## Companion finding: L14

L5 is the parent for L14 (Hidden Entry Point Mismatch). When the
primitive classification is `bin-system-shadow`, `bin-hidden-target`,
or `exports-divergence`, L5 emits BOTH an L5 finding (manifest
confusion as an attack class) AND an L14 finding (the specific
entry-point mismatch). L14 is registered as a stub TypedRuleV2 in
its own directory — its analyze() returns [] because the findings
it would produce are emitted here. This matches the wave-2
companion-rule pattern (I1→I2, F1→F2/F3/F6).

## Why confidence is capped at 0.85

A prepublish script may legitimately rewrite package.json (version
stamping, generating types entries, adjusting the `files` field for
selective publishing). A bin key named `git` may be shipped by a
package intentionally shadowing git in a developer's local
node_modules/.bin (and never globally installed). Divergent exports
may just be a legitimate CJS/ESM dual build with differing extension
conventions. Static analysis cannot always distinguish these from
the malicious primitive without runtime provenance. 0.85 preserves a
0.15 reserve for that.
