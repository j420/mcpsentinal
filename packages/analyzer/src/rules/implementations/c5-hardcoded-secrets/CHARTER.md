---
rule_id: C5
interface_version: v2
severity: critical

threat_refs:
  - kind: paper
    id: GitGuardian-State-Of-Secrets-Sprawl-2024
    url: https://www.gitguardian.com/state-of-secrets-sprawl-report-2024
    summary: >
      GitGuardian's 2024 State of Secrets Sprawl Report: 12.8 million new
      hardcoded credentials were pushed to public GitHub repositories in 2023,
      up 28% year over year. Public MCP servers are a particular exposure
      surface because they frequently aggregate credentials for downstream
      services (databases, SaaS APIs, cloud providers) that the agent operates
      on behalf of the user.
  - kind: spec
    id: OWASP-MCP07-insecure-config
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP07 — Insecure Configuration. Hardcoding of API
      keys / tokens / private keys is explicitly called out as the worst
      offender in the category: the secret is exposed to every developer
      with read access to the repository, to every fork, to every CI
      artefact, and to every historical commit.
  - kind: spec
    id: CWE-798-hardcoded-credentials
    url: https://cwe.mitre.org/data/definitions/798.html
    summary: >
      CWE-798 Use of Hard-coded Credentials. The canonical weakness class
      for this rule. Auditors expect findings to name the credential format
      (AWS AKIA, OpenAI sk-, Anthropic sk-ant-, GitHub PAT, PEM private
      key) and to carry a confidence signal stronger than "this string
      looks long".

lethal_edge_cases:
  - >
    Test fixture camouflage — a file named src/api-client.test.ts contains
    a credential-like token. A filename-only test-file skip lets the finding
    fire on a legitimate test fixture. The rule must confirm test-nature
    structurally (vitest/jest imports + describe/it/test top-level calls)
    before downgrading.
  - >
    .env.example / placeholder file — a file named .env.example contains
    lines like `ANTHROPIC_API_KEY=sk-ant-REPLACE-ME-xxxxxxxxxxxxxxxxxx`.
    A token-shape match would fire on the example. The rule must both
    check the filename shape AND scan the value for placeholder markers
    (REPLACE, PLACEHOLDER, xxxxx, ${…}, <…>, your_…_here) before emitting
    a critical finding.
  - >
    Split across template-literal parts — `const key = "sk-ant-" + someVar;`
    or `const key = \`sk-ant-\${partial}\`;`. A naïve scan of string
    literals misses this because neither part on its own is a secret. The
    rule must flag the PREFIX literal and downgrade confidence for the
    concatenation pattern — it cannot prove a credential was assembled but
    can prove a recognisable prefix was present on an assignment.
  - >
    Base64-wrapped secret inside a JSON string — `{"auth":
    "c2stYW50LWxvbmctYmFzZTY0LXRva2VuLXN0cmluZy1oZXJl"}`. Pure prefix
    matching misses this. The rule reports any sufficiently long string
    literal with ≥4.5 bits/char Shannon entropy as a SECONDARY finding and
    leaves it at lower confidence — the high entropy is suspicious but not
    proof without a prefix match.
  - >
    Pre-commit-hook-stripped secret — an attacker knows a pre-commit hook
    replaces sk- prefixes with "STRIPPED" but neglects the GitHub PAT
    ghp_ prefix. The rule covers ≥14 concrete token-format specs so a
    gap in one stripping rule does not blind the scanner to the rest.
  - >
    Low-entropy legitimate identifier — a constant like
    `const sessionPrefix = "abcdefghijklmnopqrst";` shares a shape with
    an opaque token but has low entropy. The rule applies a 3.5 bits/char
    Shannon floor on generic-pattern matches so low-entropy identifiers
    do not fire critical findings.

edge_case_strategies:
  - structural-test-file-nature     # AST-detected vitest/jest use, not filename
  - placeholder-marker-detection    # skip .env.example, REPLACE-ME, your_*_here
  - prefix-literal-recognition      # 14 concrete token-format specs in data/
  - entropy-minimum-threshold       # Shannon ≥3.5 bits/char for generic match
  - entropy-bonus-high              # Shannon ≥4.5 bits/char raises confidence
  - comment-line-skip               # AST-confirmed comments do not fire

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - token_format_match
    - entropy_score
    - placeholder_marker_absent
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Every mainstream IDE / pre-commit hook / git server blocks commits
    that contain strings matching high-confidence credential formats,
    AND every major CI provider scans forks for the same shapes before
    accepting them. Until both halves exist the rule continues to earn
    its critical severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# C5 — Hardcoded Secrets in Source Code

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available for static inspection.

## What an auditor accepts as evidence

An OWASP MCP07 / CWE-798 auditor will not accept "a string that looks
like a token". They accept:

1. **Source position** — a `source`-kind Location naming the file and
   line where the credential appears. Auditors must be able to jump to
   the line without re-running the scanner.

2. **Token-format match** — the rule declares WHICH of the 14 concrete
   credential formats matched: prefix (`sk-ant-`, `AKIA`, `ghp_`, `SG.`,
   …), expected length window, and alphabet. Unknown shapes emit at
   most medium severity; only recognised shapes emit critical.

3. **Entropy corroboration** — for generic-pattern matches
   (`api_key = "..."`, `password = "..."`), Shannon entropy of the
   value must be ≥ 3.5 bits/char to fire and ≥ 4.5 to boost confidence.
   Below the floor the rule stays silent — identifiers, placeholders,
   and trivial passwords are not credentials.

4. **Placeholder-marker absence** — the rule checks the value AND the
   surrounding line for placeholder markers (REPLACE, xxxxx, your_*_here,
   example, sample, dummy, placeholder). Any hit suppresses the finding.

5. **Mitigation status** — the rule records, on the chain, whether the
   file contains an environment-variable read for the same identifier
   name (process.env.X / os.environ.get("X")). "Secret also read from
   env" does not clear the finding but changes the remediation.

6. **Impact scenario** — a concrete description of what an attacker
   obtains (AWS console access, OpenAI account billing fraud, GitHub
   push to private repositories, Stripe live-mode charges).

## What the rule does NOT claim

- It does not decrypt or use the credential.
- It does not connect to the target service to confirm validity.
- It does not find obfuscated / base64-encoded secrets behind only
  entropy signal — those require the prefix match AND entropy to emit
  critical severity.

## Why confidence is capped at 0.85

Entropy is probabilistic, placeholder detection is heuristic, and
legitimate high-entropy values exist (cryptographic hashes, binary
fingerprints). The 0.85 cap preserves room for those false-positive
scenarios. Findings with a recognised credential prefix (AKIA, sk-ant-,
ghp_, PEM private key) receive a positive factor that lifts confidence
toward (but not above) the cap.
