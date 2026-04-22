---
rule_id: I11
interface_version: v2
severity: high

threat_refs:
  - kind: cve
    id: CVE-2025-53109
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53109
    summary: >
      Anthropic filesystem MCP server root boundary bypass. Roots are
      the declared filesystem scope for the server; overly broad roots
      (/, /etc, ~) amplify the blast radius of ANY bypass by expanding
      the data surface the server can read once the boundary is
      compromised.
  - kind: cve
    id: CVE-2025-53110
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53110
    summary: >
      Companion filesystem MCP server path traversal. Reinforces
      CVE-2025-53109 — roots must be narrowed to the minimum scope
      required for the server's declared function.
  - kind: spec
    id: MCP-Roots-2025-03-26
    url: https://modelcontextprotocol.io/specification/2025-03-26/server/roots
    summary: >
      MCP roots primitive specification. The spec defines roots as
      server-declared filesystem scopes; clients use roots for
      boundary enforcement only when the server's own resolver is
      not trustworthy. Declaring a sensitive root widens the
      client's trust surface by exactly the server's process
      permissions at the path.

lethal_edge_cases:
  - >
    file:/// root declaration — the server claims scope over the
    entire filesystem the process can read. Any file-read tool on
    this server can serve /etc/passwd, /etc/shadow, /root/.bash_history,
    or a Kubernetes projected service-account token from
    /run/secrets/...
  - >
    ~/.ssh root declaration — the server declares it can read SSH
    keys. Even if the intended purpose is "offer a UI to list hosts",
    the declaration puts id_rsa in scope. CVE-2025-68144 (J2
    companion) demonstrated the destruction path when .ssh is writable.
  - >
    /etc root declaration — system configuration including resolv.conf,
    nsswitch.conf, crontab entries, network interface config. The
    MCP server does not need this unless it is a system-administration
    server (rare).
  - >
    ~/.aws root — AWS credentials file, session tokens, config
    profiles. Compromise grants cloud-account-level access.
  - >
    /proc root — per-process memory maps, environment variables,
    file descriptor tables. /proc/<pid>/environ leaks any other
    process's secrets on the same host.
  - >
    Multiple narrow roots that TOGETHER span a sensitive directory —
    e.g. /etc/hosts + /etc/resolv.conf + /etc/nsswitch.conf. The
    individual roots pass a per-entry sensitive-path check but the
    combined coverage is ~= "/etc". The charter detects this as a
    multi-root aggregate signal.

edge_case_strategies:
  - sensitive-path-catalogue-match
  - multiple-narrow-roots-aggregate
  - false-positive-fence-demotion
  - ssh-aws-cloud-cred-severity-bump
  - root-kind-taxonomy-in-factor

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - sensitive_root_matched
    - charter_confidence_cap
  location_kinds:
    - resource

obsolescence:
  retire_when: >
    MCP clients enforce OS-level sandbox boundaries (seccomp, Linux
    mount namespaces, macOS sandbox_init) BEFORE resolving any server
    tool-call, so declared roots are advisory and the actual fs
    access is hard-bounded by the client's sandbox.
---

# I11 — Over-Privileged Root

**Author:** Senior MCP Protocol Threat Researcher persona.

Roots declare the server's intended filesystem scope. Overly broad
roots (e.g. /, /etc, ~/.ssh) make every downstream path-traversal
or tool-parameter bug blast-radius equal to the server's process
permissions at the path — CVE-2025-53109 showed this catastrophically
against the Anthropic filesystem MCP server.

Detection cross-references the `SENSITIVE_ROOT_PATHS` catalogue
in `_shared/protocol-shape-catalogue.ts` with per-entry false-
positive fences. Confidence cap **0.90** — the path match is
effectively boolean.
