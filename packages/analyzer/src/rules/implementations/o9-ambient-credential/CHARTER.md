---
rule_id: O9
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: MITRE-AML.T0057
    url: https://atlas.mitre.org/techniques/AML.T0057
    summary: >
      MITRE ATLAS AML.T0057 — LLM Data Leakage. The user's home
      directory holds the ambient credential store every CLI tool
      trusts: .aws/credentials, .ssh/id_rsa, .kube/config, .git-
      credentials, .docker/config.json. An MCP server that reads
      any of these inherits delegated authority the user never
      explicitly granted the tool.
  - kind: spec
    id: CWE-522
    url: https://cwe.mitre.org/data/definitions/522.html
    summary: >
      CWE-522 — Insufficiently Protected Credentials. The credential
      files exist precisely because the user chose to persist their
      authentication material on disk for CLI tools to find. A
      malicious MCP server reading them is the direct exploit of
      that "trusted" placement.
  - kind: spec
    id: OWASP-MCP04
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 — MCP04 Data Exfiltration. Ambient-credential
      theft is the highest-value attack surface on user machines —
      a single read gives the attacker cloud, source-control, and
      Kubernetes access all at once.

lethal_edge_cases:
  - >
    Direct fs read of cloud credentials — `fs.readFileSync("~/.aws/credentials")`,
    `readFileSync(path.join(homedir(), ".aws", "credentials"))`,
    `open("$HOME/.aws/credentials")`. These files hold AWS access
    keys and session tokens the attacker can use against every AWS
    account the user has configured.
  - >
    SSH key theft — `fs.readFileSync("/home/<u>/.ssh/id_rsa")`,
    `readFileSync("~/.ssh/id_ed25519")`. An SSH private key enables
    direct authentication as the user against every host they've
    ever configured — persistent account takeover.
  - >
    Kubernetes / Docker config theft — `.kube/config`,
    `~/.docker/config.json`. The kubeconfig gives full cluster
    access; the docker config holds registry auth tokens. Both
    feed downstream privilege-escalation chains.
  - >
    GOOGLE_APPLICATION_CREDENTIALS indirection — reading the file
    path named in the env var rather than the well-known `.aws`
    path. The rule inspects both forms: a direct path-literal read
    AND a read whose argument is the env-var identifier.
  - >
    Legitimate single-server-author-owned config — a server that
    legitimately stores its own credentials in a server-scoped
    location (e.g. `./server-config/token.json`). The gather step
    only fires on *ambient user-scoped* paths; server-local paths
    do not match the catalogue.

edge_case_strategies:
  - ambient-path-token-match          # DATA_EXFIL_SINKS "env-var" ambient-path entries
  - homedir-expansion-detection       # os.homedir() / path.join + ".aws"
  - env-var-indirection-detection     # process.env.GOOGLE_APPLICATION_CREDENTIALS
  - test-file-structural-skip

evidence_contract:
  minimum_chain:
    source: true
    propagation: true
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - ambient_credential_path_observed
    - server_process_inherits_authority
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The OS or MCP client runtime sandboxes server filesystem access
    so that ambient credential files are invisible to the server
    process, OR the MCP spec declares credential-file access as a
    user-approved capability. Neither exists as of 2026-04.
---

# O9 — Ambient Credential Exploitation

## Threat Model

MCP servers run with the user's filesystem authority. Every CLI
tool the user has ever configured on this machine has left its
credentials on disk — typically inside the user's home directory
in a well-known relative path. An attacker-controlled MCP server
can simply open those paths:

- `~/.aws/credentials` — AWS access keys + session tokens
- `~/.ssh/id_rsa`, `~/.ssh/id_ed25519` — SSH private keys
- `~/.kube/config` — Kubernetes cluster credentials
- `~/.docker/config.json` — container registry tokens
- `$GOOGLE_APPLICATION_CREDENTIALS` path — GCP service account JSON

A single `fs.readFileSync` lifts the entire credential inventory
of any CLI the user has installed.

## Detection Strategy — Path-Shape AST

The rule inspects every call to a filesystem read primitive (`fs.readFileSync`,
`fs.readFile`, `fsPromises.readFile`, the bare `readFile` /
`readFileSync` import, Python's `open`) and classifies the first
argument:

1. **String literal with an ambient-path token** — `"~/.ssh/id_rsa"`,
   `"/Users/jane/.aws/credentials"`, `"$HOME/.kube/config"`.
2. **Template literal with the env-var root** — `` `${homedir()}/.aws/credentials` `` .
3. **path.join / os.path.join including an ambient token** —
   `path.join(homedir(), ".aws", "credentials")`.
4. **Env-var indirection** — argument is `process.env.GOOGLE_APPLICATION_CREDENTIALS`
   or `process.env.AWS_SHARED_CREDENTIALS_FILE`.

All vocabulary comes from the shared `DATA_EXFIL_SINKS` "env-var"
entries. Zero regex literals.

## Confidence Cap

**0.85** — the ambient-path signal is very strong; only
legitimate case is a server whose own configuration happens to
live at an ambient path (vanishingly rare). The cap holds
auditor headroom for that edge case.
