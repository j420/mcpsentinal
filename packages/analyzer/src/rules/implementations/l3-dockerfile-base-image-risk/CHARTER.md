---
rule_id: L3
interface_version: v2
severity: high
owasp: MCP10-supply-chain
mitre: AML.T0017
risk_domain: supply-chain-security

threat_refs:
  - kind: cve
    id: CVE-2019-5736
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-5736
  - kind: spec
    id: NIST-SP-800-190
    url: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf
    summary: >
      NIST SP 800-190 "Application Container Security Guide" §4.1.2
      specifies that containers MUST be built from verified base images,
      that image provenance MUST be recorded, and that mutable tags are
      an explicit risk because the bytes under a tag can change without
      the consumer's knowledge. Pinning to a content-addressable digest
      is the canonical remediation.
  - kind: spec
    id: CIS-Docker-Benchmark-4.2
    url: https://www.cisecurity.org/benchmark/docker
    summary: >
      CIS Docker Benchmark §4.2 "Ensure that containers use only trusted
      base images" — explicit guidance that FROM instructions without a
      SHA256 digest expose the image to supply chain substitution. The
      control references Docker Content Trust and digest pinning as the
      two compensating mitigations.
  - kind: paper
    id: Flare-Research-2025-DockerHub
    url: https://flare.io/learn/resources/blog/docker-hub-secrets
    summary: >
      Flare Research (2025) enumerated 10,000+ Docker Hub images that had
      secrets baked into a base-image layer. Dependent images pulling by
      mutable tag silently inherited the leaked credentials when the
      upstream image was updated, with no Dockerfile change on the
      consumer side. This is the live-threat model this rule addresses.

lethal_edge_cases:
  - >
    Digest drift on one stage — a multi-stage build pins the final
    runtime stage to a digest but leaves the builder stage on a mutable
    tag. An attacker who compromises the builder tag can inject
    backdoored binaries into the ARTIFACT the pinned stage then COPYs,
    so pin-of-final-stage is not a complete mitigation. The rule must
    flag every unpinned stage, not just the runtime one.
  - >
    Registry substitution via argument — FROM $BASE_IMAGE where
    $BASE_IMAGE is defined with ARG and defaults to an unpinned public
    image. An attacker with build-time control over the ARG value can
    swap the base image wholesale. A surface check that only looks at
    literal FROM arguments misses this; the rule must also flag FROM
    instructions whose image reference contains an unresolved ARG.
  - >
    "Scratch" confusion — attackers rename a real base image to literal
    "scratch-extras" / "scratch-python" hoping the rule skips them via
    the scratch allowlist. The rule MUST allowlist ONLY the exact image
    name "scratch" (case-sensitive, no tag, no digest) — not any image
    whose name starts with "scratch".
  - >
    Dev tag camouflage — tags like "latest-prod", "lts-stable",
    "release-latest" look pinned but resolve to the same mutable ref
    as "latest". The rule must treat any tag whose final token matches
    a known mutable keyword (latest / stable / lts / edge / nightly /
    dev / beta / alpha / rc / canary / next / current / mainline) as
    mutable, regardless of suffix ordering.
  - >
    Platform-qualified FROM — `FROM --platform=linux/amd64 image:tag`.
    A naive parser that splits on whitespace and reads the second token
    gets "--platform=linux/amd64" as the image. The rule must strip
    `--platform=`, `--build-arg=`, and similar flags before extracting
    the image reference. Miss this and architectural-cross builds
    silently bypass the rule.

edge_case_strategies:
  - multi-stage-per-stage-check
  - arg-reference-flag
  - scratch-exact-match
  - mutable-tag-suffix-tokenisation
  - flag-stripping-before-image-extraction

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - unpinned_base_image
    - mutable_tag_detected_or_no_tag
    - digest_present_elsewhere_in_dockerfile
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Docker Content Trust (or an OCI-spec successor) is enforced at the
    registry level such that pulls without a verified, content-addressable
    digest are refused by every compliant registry — at which point
    Dockerfile-side pinning is belt-and-braces, not the control surface.
---

# L3 — Dockerfile Base Image Supply Chain Risk

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** Dockerfiles packaged alongside MCP server source that are
consumed at build time by a registry push, CI, or developer `docker build`.

## What an auditor accepts as evidence

An NIST SP 800-190 / CIS Docker §4.2 auditor will not accept
"repository contains a Dockerfile with 'FROM' in it" as evidence of a
supply-chain control failure. They will accept:

1. **Scope proof** — the finding names a specific FROM instruction, with
   a `source`-kind Location pointing at the exact file and line. Multi-stage
   builds produce one finding per unpinned stage, because every stage is
   an independent supply-chain trust boundary.

2. **Gap proof** — the finding names either (a) the missing tag (implicit
   `:latest` reference) or (b) the matched mutable keyword inside the tag.
   Case-insensitive match against a canonical token set, not a free-text
   regex — the no-static-patterns guard requires a typed Record.

3. **Mitigation check** — when some FROM instructions in the same Dockerfile
   DO pin a digest, the finding records that fact. A Dockerfile where every
   stage pins a digest is clean; a Dockerfile where two of three stages pin
   is partially mitigated (lower confidence). A Dockerfile with no digest
   anywhere is the worst case.

4. **Impact statement** — the concrete scenario: a compromised registry or
   a maintainer-side tag push substitutes a malicious image under the same
   reference. The next build pulls the malicious image. Every workload
   derived from the affected layer executes attacker-controlled code.
   Cross-referenced to AML.T0017 (Supply Chain Compromise) and the
   CVE-2019-5736 runC escape precedent that elevates a malicious image
   from "arbitrary in-container code" to "host-root RCE".

## What the rule does NOT claim

- It does not scan the REMOTE registry to verify whether the tag resolves
  to a trusted digest today. That is a runtime check. The rule only sees
  the source file.
- It does not claim every mutable-tag usage is an exploit — many developers
  pin intentionally to `:latest` during local iteration. The finding is
  "supply chain risk present," not "active compromise".

## Why confidence is capped at 0.85

The best static proof available is "this Dockerfile declares an unpinned
base image". What the rule cannot see: (a) whether the consumer of the
built image re-pins via registry-side policy (Harbor, ECR, Quay image
policy), (b) whether DCT is enabled on the builder, (c) whether the image
is immediately retagged with a digest by a downstream pipeline. Capping at
0.85 preserves room for that out-of-file mitigation rather than
overclaiming.
