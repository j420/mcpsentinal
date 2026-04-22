---
rule_id: P5
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0057
risk_domain: container-runtime

threat_refs:
  - kind: spec
    id: CWE-538
    url: https://cwe.mitre.org/data/definitions/538.html
    summary: >
      CWE-538 "Insertion of Sensitive Information into Externally-
      Accessible File or Directory" is the parent weakness for every
      build-layer credential leak this rule detects. Dockerfile ARG
      and ENV values persist in image layer history and are retrieved
      via `docker history --no-trunc` by anyone with image pull access
      (most registries publish images readably to the whole dev team).
  - kind: spec
    id: Docker-BuildKit-Secrets-Documentation
    url: https://docs.docker.com/build/building/secrets/
    summary: >
      Docker BuildKit provides `RUN --mount=type=secret` specifically
      to solve the build-layer leak problem. The secret is available
      during the RUN step but is NOT written into the image layer.
      Any Dockerfile that passes credentials via ARG / ENV is choosing
      the pre-BuildKit pattern; the remediation is to migrate to
      BuildKit mount-type secrets, not to post-hoc `docker history`
      sanitise.
  - kind: paper
    id: 42Crunch-Dockerfile-Secret-Leak-2023
    url: https://42crunch.com/container-image-secrets-leak/
    summary: >
      42Crunch research catalogued hundreds of public DockerHub images
      leaking cloud credentials, npm tokens, SSH keys, and database
      URLs via ARG / ENV layer inspection. MCP servers are especially
      affected because many run inside development-team-private images
      that are still exposed to the entire dev team.

lethal_edge_cases:
  - >
    ARG with default value — `ARG SECRET=default-value` sets a default
    that is baked into the image layer even without `--build-arg`
    overrides. The default CAN be empty (a signal of "populate me via
    --build-arg") but is often left as the actual credential during
    development. The rule flags ARG even with empty or placeholder
    values because the name alone indicates intent.
  - >
    COPY of .env / credentials files — `COPY .env /app/` or
    `COPY secrets.json /etc/` bake the whole file into the image layer.
    A .dockerignore that omits .env files compounds the leak.  The
    rule flags COPY of any file matching credential-name conventions
    and recommends a .dockerignore audit in remediation.
  - >
    Multi-stage image holdover — a builder stage sets ENV DATABASE_URL
    then the final stage does FROM scratch COPY --from=builder. The
    final image may or may not include the ENV depending on stage
    isolation. The rule flags the ENV declaration in ANY stage because
    multi-stage isolation is operator-controlled and frequently broken.
  - >
    --secret flag false-alarm — `RUN --mount=type=secret,id=npmrc cat /run/secrets/npmrc`
    is the CORRECT BuildKit pattern and must NOT trigger. The rule
    exempts lines containing the `--mount=type=secret` token even when
    they reference credential-like file paths.
  - >
    RUN env SECRET=... — `RUN SECRET=deadbeef npm install` sets the
    secret for that one command but ALSO bakes the credential into
    the command history layer visible to `docker history`. The rule
    flags inline credential assignment on a RUN line even without ARG
    or ENV.

edge_case_strategies:
  - arg-default-value-detection
  - copy-credential-file-detection
  - multi-stage-isolation-conservative
  - buildkit-secret-mount-exemption
  - run-inline-assignment-detection

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - variant
    - credential_name
    - buildkit_secret_nearby
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Docker removes legacy ARG / ENV support AND every registry enforces
    docker-history-scanning at push time. Neither is on the near-term
    roadmap; until both land, this rule remains front-line.
---

# P5 — Secrets in Container Build Layers

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** Dockerfiles (including multi-stage builds), docker-compose
files that pass secrets via environment blocks, shell scripts that
invoke docker build with --build-arg credentials.

## What an auditor accepts as evidence

A CWE-538 / Docker-BuildKit-Secrets-Documentation auditor wants:

1. **Scope proof** — specific Dockerfile line carrying a credential-
   like identifier, with a `source`-kind Location. The rule reports
   each ARG / ENV / COPY site as a separate finding.

2. **Gap proof** — the identifier matches the credential-name
   vocabulary (PASSWORD / SECRET / TOKEN / KEY / CREDENTIALS / DATABASE_URL
   etc.) AND the line is NOT a BuildKit `--mount=type=secret` usage.

3. **Impact statement** — concrete extraction scenario: `docker pull`
   + `docker history --no-trunc` retrieves every ARG default and ENV
   value. For COPY'd .env files, `docker cp` or `docker save | tar -x`
   reveals the file contents.

## What the rule does NOT claim

- It does not verify whether a final multi-stage image actually
  contains the credential — isolation is operator-controlled and the
  analyzer conservatively flags any declaration in any stage.
- It does not audit .dockerignore contents — that would require a
  separate cross-file check; the remediation text mentions it.

## Why confidence is capped at 0.80

The identifier-name heuristic produces occasional false positives
(e.g. `ARG GITHUB_TOKEN_SCOPE` as a scope descriptor, not the token).
0.80 preserves room for those without suppressing the posture finding.
