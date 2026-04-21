---
rule_id: C2
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-53109
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53109
  - kind: cve
    id: CVE-2025-53110
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53110
  - kind: spec
    id: OWASP-MCP05-privilege-escalation
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP05 — Privilege Escalation. Unconstrained file
      path construction lets an MCP server read /etc/passwd,
      ~/.ssh/id_rsa, or write into a parent directory — the classic
      privilege-escalation surface for MCP servers exposed as filesystem
      proxies. The Anthropic filesystem MCP server (CVE-2025-53109/53110)
      is the canonical 2025 example.
  - kind: spec
    id: CWE-22-path-traversal
    url: https://cwe.mitre.org/data/definitions/22.html
    summary: >
      CWE-22 "Improper Limitation of a Pathname to a Restricted Directory
      ('Path Traversal')". The canonical weakness class for this rule.
      Auditors expect findings to cite CWE-22 and the lethal edge-case
      list below for traversal techniques (null-byte termination,
      URL-encoded dot-dots, mixed separators, Windows UNC \\?\ prefix,
      symlink follow).

lethal_edge_cases:
  - >
    path.resolve without a base clamp — `path.resolve(userInput)` returns
    an absolute path but does NOT check that the result is inside the
    intended base directory. The analyser treats `path.resolve` as a
    "resolve" sanitiser in its default sinks, which is wrong when no
    `startsWith(baseDir)` follows. The charter mandates a dedicated
    charter-unknown branch for `resolve` so the finding still fires when
    no base-directory check is observed on the path.
  - >
    Null-byte termination — `fs.readFile(userPath + "\x00safe.txt")`.
    Historically some Node.js releases ignored the post-NUL portion of
    the path, so an attacker could read /etc/passwd\x00public.html.
    Modern Node throws on NUL bytes, but the MCP server's own
    input-decode (URL-decode, JSON parse) may strip / preserve NULs
    inconsistently. The rule flags any `\x00` / `%00` reaching a file
    sink.
  - >
    URL-encoded traversal — `%2e%2e%2f` / `%2e%2e/` / literal `..%2f`.
    Servers that decode once and then pass the result to fs APIs
    without re-validating are vulnerable. The analyser covers both
    the decoded-then-reinspected flow (via `analyzeTaint` source
    categories) and the encoded literal case.
  - >
    Windows UNC prefix — `\\?\C:\Windows\System32` or `\\server\share`.
    path.resolve will preserve the UNC form; on Windows runtimes this
    bypasses POSIX-style `../` validation because the path has no
    dot-dot sequences. Flagged as a lethal edge case because Docker /
    Windows hybrid deployments do exist.
  - >
    Symlink follow — the MCP server `readFile`s a path the user
    controls, and the path points at a symlink the user also controls
    (e.g. through a previous upload tool). The sink flag fires; the
    auditor needs the verification step that calls out "audit symlink
    handling on this path" explicitly because a static analyser cannot
    prove the flow is safe without follow-symlink controls.
  - >
    Dependency on defence-in-depth that isn't there — the programmer
    believed chroot / unshare / Docker user namespace was enough. In
    practice MCP servers are often deployed as plain Node processes.
    The charter rejects "host is sandboxed" as a mitigation signal —
    file sinks accepting user paths remain critical.

edge_case_strategies:
  - ast-taint-file-sink                # analyzeASTTaint file_write / file_read
  - lightweight-path-access-fallback   # analyzeTaint path_access fallback
  - resolve-without-clamp              # "resolve" sanitiser downgraded to informational only when a startsWith check follows
  - literal-traversal-substring        # structural substrings for '..' / '%2e%2e' / '\x00' / UNC

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - ast_confirmed
    - lightweight_taint_fallback
    - interprocedural_hops
    - unverified_sanitizer_identity
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Node.js / Python / Deno / Bun all expose a first-class `safeReadFile`
    API that REQUIRES a base directory and returns an error on any
    traversal attempt — AND the MCP SDK generators only emit that API
    when a tool is declared filesystem-scoped. Until both halves exist
    C2 retains critical severity.
---

# C2 — Path Traversal (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source files are available and which call a filesystem read/write API.

## What an auditor accepts as evidence

An OWASP MCP05 / CWE-22 / CVE-2025-53109 auditor accepts a structured
chain showing:

1. **Source** — a source-kind Location naming the AST node where
   untrusted data enters (`req.body.*`, MCP tool argument,
   `process.env.*`, `request.form[…]`, Python `request.args[…]`).

2. **Propagation** — one link per hop (assignment, destructure,
   template-embed, function-call, return). Direct single-line flows
   have zero propagation links and exploitability = "trivial".

3. **Sink** — a source-kind Location on the fs call:
   `fs.readFile` / `readFileSync` / `writeFile` / `writeFileSync` /
   `createReadStream` / `createWriteStream` / Python `open()`. The
   sink_type on the chain is `file-write` (the EvidenceLink
   discriminator does not have a dedicated `file-read` variant; the
   direction is encoded in `observed` + the `file_read` vs `file_write`
   category inside the taint engine).

4. **Mitigation** — recorded present/absent. "Present" means a charter-
   audited sanitiser lies on the path (path.relative + startsWith clamp,
   a canonicalise-then-validate helper). "resolve" / "normalize" alone
   are NOT on the charter list because neither proves the result is
   inside the base directory — the charter-unknown branch documents
   this distinction.

5. **Impact** — `privilege-escalation`, scope `server-host`. Read
   traversal exfiltrates /etc/passwd / ~/.ssh/id_rsa / MCP server
   secrets. Write traversal overwrites systemd units or adds SSH keys.

6. **Verification steps** — one per AST hop + an explicit step for
   the sanitiser (or its absence).

## Why confidence is capped at 0.92

AST-confirmed in-file taint is the strongest static proof. The 0.08
gap exists for:

- OS-level defences the static analyser cannot see (chroot, unshare,
  Docker user namespace, bind-mount read-only);
- web-framework path-normalising middleware (express-static with root);
- Windows runtimes where UNC prefixes bypass POSIX dot-dot checks.

The cap is visible as a `charter_confidence_cap` factor on every
AST-confirmed chain whose raw confidence exceeds it.
