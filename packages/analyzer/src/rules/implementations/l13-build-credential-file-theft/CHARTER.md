---
rule_id: L13
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-55155
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-55155
  - kind: incident
    id: shai-hulud-npmrc-2025-09
    url: https://blog.socket.dev/shai-hulud-npm-worm-analysis
    summary: >
      Shai-Hulud self-replicating npm worm, September 2025. Compromised
      packages read ~/.npmrc during their postinstall / build phase,
      extracted the _authToken, and exfiltrated it to an attacker-
      controlled endpoint. The stolen tokens were then used to re-publish
      the worm inside other packages the victim maintained, propagating
      across the npm registry with zero user interaction.
  - kind: paper
    id: Trellix-npm-hijack-2025
    url: https://www.trellix.com/blogs/research/npm-account-hijacking-2025
    summary: >
      Trellix research on the npm account-hijacking chain. Root cause
      across three disclosed incidents was attacker access to a
      publisher's .npmrc auth token — the exact file L13 forbids reading
      in MCP server code.

lethal_edge_cases:
  - >
    Cred file read via symlink — the server reads a path it considers
    safe (e.g. /app/.npmrc), but the target is a symlink whose link
    target is a REAL ~/.npmrc outside the sandbox. A static rule that
    whitelists "local" paths misses this; the rule must flag ANY file
    read whose path string includes the sensitive filename suffix
    regardless of directory prefix.
  - >
    .npmrc in Dockerfile COPY — the Dockerfile contains `COPY .npmrc
    /root/.npmrc`. Even if the runtime code never reads the file
    directly, the credential is now baked into the image and any
    untrusted container reader can extract it. The rule scans build-
    time config (Dockerfile, docker-compose.yml, ci.yml) for lines
    that copy a credential file into the image.
  - >
    Ambient creds from parent dir — the server walks up the filesystem
    tree looking for an .npmrc. On CI runners the parent dir may
    contain a CI-global token (e.g. /home/runner/.npmrc). The rule
    flags any fs.readFile call whose path contains a credential
    filename substring even when the path is ../ or ./.npmrc.
  - >
    Exfil via workflow artifact — the server reads the credential file
    and writes it to a GitHub Actions artifact (uploadArtifact /
    actions/upload-artifact). Artifacts are reachable by anyone with
    repository read access and persist for 90 days. The rule detects
    the flow when the sink is a network call OR a file-write whose
    target path contains "artifact".
  - >
    Plaintext env echo — `echo "$NPM_TOKEN" >> secrets.txt; upload ...`.
    This bypasses a pure file-read heuristic because the source is
    process.env, not a file. Related coverage lives in L9 (CI secret
    exfiltration); L13 stays focused on the file-read surface so
    findings remain orthogonal.

edge_case_strategies:
  - cred-file-substring-match
  - ast-taint-file-read-to-network-sink
  - dockerfile-copy-cred-file-scan
  - cred-read-without-fd-scoping
  - lightweight-file-read-fallback

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - cred_file_path_substring
    - taint_flow_to_network_sink
    - no_input_validation_on_exfil
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    The npm / pnpm / pypi toolchains adopt OIDC short-lived tokens for
    publish by default (no long-lived .npmrc / .pypirc tokens on
    developer machines), AND the underlying file formats are no longer
    used to store bearer credentials.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# L13 — Build Credential File Theft

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source and build scripts; specifically any
file-read operation whose path contains a credential-file name
substring.

## Distinct from C5 / L9

- C5 detects hardcoded secrets in source. L13 does not flag the
  secret itself; it flags code that reads a FILE known to contain one.
- L9 detects CI secret env-var exfiltration (`echo "$NPM_TOKEN"`). L13
  stays on the file-read surface: `readFile(".npmrc")` + a network
  sink.

## What an auditor accepts as evidence

1. **File-read call** — a `source`-kind Location at the fs.readFile /
   readFileSync / open / cat call whose path argument contains a
   credential-file substring (`.npmrc`, `.pypirc`, `.docker/config.json`,
   `.ssh/id_`, `.aws/credentials`, `~/.config/gh/hosts.yml`).

2. **Taint path to a network sink OR a propagation observation** — the
   finding emits either (a) a full source→network-sink taint chain via
   the shared taint-rule-kit, OR (b) a structural "credential file
   read without scope" finding when no network sink is reachable. Case
   (b) has a propagation link noting "content loaded into memory
   without clear scope".

3. **Mitigation check** — the rule reports whether the read is followed
   by an explicit scope reduction (close() / unref() / fd cleanup) and
   whether the path is compared against a deny-list of credential
   filenames. Absence is the finding.

4. **Impact** — tied to CVE-2025-55155 / Shai-Hulud: stolen publish
   token enables a self-propagating supply-chain compromise.

## Why confidence is capped at 0.85

Legitimate tools (npm's own `npm config`, CI setup scripts that write
`.npmrc` to establish credentials) READ these files. The rule cannot
always distinguish "writing a .npmrc to enable publish" (benign) from
"reading a .npmrc to exfiltrate it" (malicious) without a full runtime
trace. The 0.85 cap preserves room for that distinction.
