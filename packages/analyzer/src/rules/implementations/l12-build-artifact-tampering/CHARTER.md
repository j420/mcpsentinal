---
rule_id: L12
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-30066
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-30066
  - kind: paper
    id: SLSA-Build-Integrity-v1.1
    url: https://slsa.dev/spec/v1.1/requirements#build-integrity
    summary: >
      SLSA (Supply-chain Levels for Software Artifacts) v1.1 Build
      Integrity requirements. Level 2 requires the build service to
      produce signed provenance covering the build process; Level 3
      requires the build to be isolated. Post-build artifact
      tampering violates both — the provenance attestation covers
      the pre-tamper bytes, so consumers validating provenance still
      install the tampered output.
  - kind: incident
    id: Shai-Hulud-npm-worm-2025-09
    url: https://blog.socket.dev/shai-hulud-npm-worm-analysis
    summary: >
      Shai-Hulud self-replicating npm worm, September 2025. The
      worm injected malicious GitHub Actions into compromised
      repositories; the actions modified built artifacts between
      the tested build step and the publish step, so tests passed
      on clean code but consumers installed the tampered output.
      This is the live exemplar of the L12 primitive.
  - kind: spec
    id: CWE-494
    url: https://cwe.mitre.org/data/definitions/494.html
    summary: >
      CWE-494 — Download of Code Without Integrity Check. Consumers
      install the tampered tarball without any independent
      verification that the bytes they run match what the tests
      validated. This is the weakness class L12 surfaces.

lethal_edge_cases:
  - >
    Tamper-after-test shape — postbuild / prepublishOnly / prepack
    runs `sed` or `awk` or `cat >> dist/*.js` AFTER `npm test` has
    completed. Tests validated the build output; the tamper step
    runs between test and pack. A linter that only checks for "sed
    in scripts" misses the ordering constraint; L12 must pair the
    observation with the lifecycle hook that guarantees post-test
    execution.
  - >
    Build tool camouflage — the script runs `tsc && sed -i …
    dist/index.js && esbuild …` in a single && chain. A pure build-
    tool check sees tsc and esbuild and passes the script as benign;
    the rule must detect the sed/awk/cat-append command irrespective
    of what else runs in the chain.
  - >
    CI-level tampering — the package.json is clean, but a GitHub
    Actions workflow runs `npm test && echo 'inject' >> dist/cli.js
    && npm publish`. Source-code-only scanners miss this. L12
    detects the same tamper pattern in .github/workflows/*.yml when
    the source_files map contains workflow content.
  - >
    Artifact fetch & modify — a workflow uses actions/download-
    artifact to pull a built bundle produced by an earlier job,
    modifies it, then uploads it for publish. The modification
    step is the L12 primitive even when the original build did
    not touch dist/. The rule flags any append/modify targeting
    dist/ build/ out/ lib/ irrespective of whether the same script
    also produced those files.
  - >
    Innocuous-looking text replace that actually strips integrity
    checks — `sed -i s/assertIntegrity/\\/\\//\\/g dist/loader.js`
    removes a runtime integrity check line. A keyword scan for "sed"
    would fire (which is correct) but a reviewer who reads the
    command might assume it is a version-stamp mutation. The rule
    records the full command text in `observed` so the reviewer
    sees exactly what is being changed.

edge_case_strategies:
  - lifecycle-order-detection
  - build-tool-camouflage
  - ci-workflow-tamper-scan
  - artifact-fetch-modify
  - full-command-observation

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - lifecycle_ordering_proof
    - build_dir_target
    - no_provenance_mitigation
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Every major registry (npm, PyPI, crates.io, go-proxy) requires
    SLSA Build Level 3 provenance covering the exact tarball bytes,
    AND the leading MCP clients refuse to install packages whose
    provenance does not pass. Until both hold, post-build tampering
    remains undetectable to consumers at install time.
---

# L12 — Build Artifact Tampering

**Author:** Senior MCP Threat Researcher.
**Applies to:** package.json publish-lifecycle scripts AND CI workflow
YAML that runs the publish pipeline. The rule looks for code that
modifies files in a build-output directory (dist/, build/, out/, lib/)
AFTER the test step has executed.

## What an auditor accepts as evidence

1. **Lifecycle ordering proof** — the finding names the specific
   lifecycle hook (postbuild / prepublishOnly / prepack / prepare)
   whose npm-defined execution ordering guarantees it runs AFTER
   `npm test` has validated the build output. Without ordering proof,
   the finding reduces to "a sed command exists" and does not
   establish the integrity gap.

2. **Build-dir target proof** — the command references one of
   dist/ build/ out/ lib/ as the modification target. L12 does NOT
   flag sed commands against source directories (src/, lib/src/)
   or against config files (tsconfig.json, package.json — L5 covers
   those). The attack vector is specifically about modifying the
   compiled, soon-to-be-published artifact.

3. **Mitigation check** — the rule reports whether `publishConfig.
   provenance: true` is set and whether SLSA-shaped attestation
   tooling is observed in the build pipeline. Provenance binds the
   build source to the tarball bytes; its absence is the finding's
   amplifier.

4. **Impact statement** — CVE-2025-30066 (tj-actions/changed-files,
   March 2025) and the Shai-Hulud worm (September 2025) are the live
   exemplars: both used post-test artifact modification to publish
   compromised code that passed CI.

## Differences from L1 and L5

- **L1** (GitHub Actions tag poisoning) flags unpinned Actions that
  could serve different code over time. L12 flags the actions'
  content — the modification command itself — regardless of how the
  action is pinned.
- **L5** (manifest confusion) flags scripts that mutate
  **package.json**. L12 flags scripts that mutate **dist/**. The
  two primitives can coexist in a single publish pipeline; each
  fires independently.

## Why confidence is capped at 0.85

Legitimate use cases exist: version stamping (`sed -i 's/0.0.0/1.2.3/g'
dist/index.js`), banner injection for licence headers, post-build
polyfill shimming. Static analysis cannot reliably distinguish these
from a credential-exfiltration banner or a removed-integrity-check
sed. 0.85 preserves a 0.15 reserve for that.
