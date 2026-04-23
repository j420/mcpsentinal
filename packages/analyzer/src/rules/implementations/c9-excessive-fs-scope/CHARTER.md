---
rule_id: C9
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: OWASP-MCP03-command-injection
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP03. While the family name is "command
      injection", the OWASP guidance covers all over-privileged
      execution surfaces including filesystem scope. An MCP server
      with root-level read or write access turns every prompt into a
      potential exfiltration of /etc/shadow, ~/.ssh/id_rsa, or the
      MCP server's own .env file.
  - kind: spec
    id: CWE-732
    url: https://cwe.mitre.org/data/definitions/732.html
    summary: >
      CWE-732 "Incorrect Permission Assignment for Critical Resource".
      An MCP filesystem tool that operates from "/" as its base
      directory grants the AI agent the same filesystem privileges as
      the MCP host process — almost always far more than the
      single-tool scope intended.
  - kind: spec
    id: CWE-668
    url: https://cwe.mitre.org/data/definitions/668.html
    summary: >
      CWE-668 "Exposure of Resource to Wrong Sphere". Listing the root
      directory exposes every file the host process can read to the AI
      agent's reasoning surface — and from there to anything the agent
      writes, logs, or echoes. The MCP threat model makes this the
      one-step exfiltration to either the user-facing response or a
      downstream tool.
  - kind: paper
    id: Anthropic-MCP-Filesystem-Bestpractice
    url: https://modelcontextprotocol.io/docs/concepts/roots
    summary: >
      Anthropic's MCP roots specification (2025-06-18) introduces the
      `roots` capability so a server can declare a bounded set of
      directories. The spec is explicit that root-level access is an
      anti-pattern — every filesystem MCP server should declare a
      restrictive root and reject any path that escapes it.

lethal_edge_cases:
  - >
    `fs.readdirSync("/")` — listing the entire root directory.
    Returns the names of every system directory; the agent then
    iteratively walks the tree on subsequent calls. The most direct
    expression of the antipattern.
  - >
    `process.chdir("/")` followed by relative-path file operations —
    the working directory becomes the root, so `fs.readFile("etc/
    passwd")` succeeds without ever using the literal string "/".
    The rule must detect `chdir("/")` itself even when no fs call
    follows it on the same line.
  - >
    `glob("/**", ...)` / `walkDir("/")` / Python `os.walk("/")` —
    enumeration patterns that recurse into every directory. Even
    read-only, the enumeration is full reconnaissance + exfiltration
    in a single call.
  - >
    `allowedPaths = ["/"]` / `BASE_DIR = "/"` — the developer thought
    they were configuring an allowlist but pointed it at the root.
    Common in early-stage MCP filesystem servers; the rule covers
    both array literals and string assignments.
  - >
    Home-directory expansion to `~` followed by tool-controlled
    suffix — `path.join(os.homedir(), tool.input.path)` lets a single
    `../../../etc/passwd` escape to root. The rule treats `homedir`
    + concatenation with user input as equivalent to root scope when
    no clamp follows.

edge_case_strategies:
  - ast-fs-call-with-root-path     # detect <fs>.{readdir,readFile,glob,walk}("/" | "/.*")
  - ast-chdir-root                 # detect process.chdir("/") / os.chdir("/")
  - ast-allowed-paths-root         # detect allowedPaths/baseDir/rootDir = "/" or ["/"]
  - python-walk-root               # Python os.walk("/") / Path("/").iterdir()
  - homedir-with-user-input        # path.join(os.homedir(), <tainted>) without clamp

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_root_pattern
    - root_call_kind
    - structural_test_file_guard
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The MCP SDK refuses to register a filesystem tool whose declared
    root is "/" (or unset, which collapses to root) AND every
    mainstream MCP filesystem server enforces a root via the
    `roots` capability declared at handshake. Until both halves
    exist, C9 retains high severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# C9 — Excessive Filesystem Scope

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which expose filesystem access
(read / write / list / walk).

## What an auditor accepts as evidence

A CWE-732 / OWASP MCP03 auditor accepts a structured chain showing:

1. **Source** — a source-kind Location naming the AST node where the
   root scope is established: a `<fs>.<method>("/")` call, a
   `process.chdir("/")` call, a `BASE_DIR = "/"` assignment, or an
   `allowedPaths = ["/"]` array literal.

2. **Sink** — the same Location: the scope-establishing operation IS
   the dangerous operation. The chain `sink_type` is `file-write`
   (we use this discriminator for both reads and writes — direction
   is encoded in the observed text).

3. **Mitigation** — recorded present/absent. "Present" means a
   subsequent path-clamp helper (`isSubpath`, `resolveWithin`,
   `safeJoin`) restricts the scope. "Absent" means no such clamp is
   visible.

4. **Impact** — `privilege-escalation`, scope `server-host`. The
   canonical scenario: agent reads ~/.ssh/id_rsa, /etc/passwd, the
   MCP server's own .env, or writes a malicious systemd unit /
   authorized_keys entry.

5. **Verification steps** — one for the root expression, one for the
   surrounding clamp search, one for the deployment scope (sandbox /
   chroot / container user).

## Why confidence is capped at 0.90

Static analysis cannot observe an OS-level chroot, an unshare
namespace, or a Docker user-namespace remap that would make root
filesystem access harmless. The 0.10 gap is reserved for those
deployment-time defences.
