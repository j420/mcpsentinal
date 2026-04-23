---
rule_id: J2
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-68143
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-68143
    summary: >
      mcp-server-git path validation bypass (chain component). Anthropic's
      official mcp-server-git allowed a tool-parameter-controlled path to
      escape the intended workspace — the first link of a three-CVE RCE
      chain. J2's detection focuses on the input surfaces that produced
      this CVE.
  - kind: cve
    id: CVE-2025-68144
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-68144
    summary: >
      mcp-server-git unrestricted git_init (chain component). git_init on
      arbitrary paths (especially `.ssh`) enables the attacker to write a
      malicious `.git/config` with `core.sshCommand` / `core.hookPath` set
      to arbitrary executable paths.
  - kind: cve
    id: CVE-2025-68145
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-68145
    summary: >
      mcp-server-git argument injection (chain component, CVSS 9.1). The
      final link: unsanitised user arguments reach git via exec, and
      `--upload-pack=CMD`, `--receive-pack=CMD`, `--exec=CMD` style flags
      turn git into an arbitrary-command runner. J2 detects this whether
      the sink is a template literal, a concat, or a spread argv.
  - kind: cve
    id: CVE-2025-6514
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6514
    summary: >
      mcp-remote OS command injection (CVSS 9.6). Cross-referenced in J2 as
      the canonical MCP-ecosystem exec-on-user-input CVE; J2 differs from
      C1 in being git-specific, but CVE-2025-6514 establishes that MCP
      servers routinely call exec on tool arguments without validation.
  - kind: spec
    id: OWASP-MCP03-command-injection
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP03. J2 is the git-wrapping-subclass
      of MCP03: argv-form spawn is fine until the first argv element is
      user-controlled and starts with `--`.

lethal_edge_cases:
  - >
    git with `-c` override — `git -c core.sshCommand=$USER_VAL fetch ...`.
    The `-c` flag sets a transient config KEY=VALUE; setting `core.sshCommand`
    here is the same exploit primitive as CVE-2025-68144 except it skips
    the filesystem `.git/config` write. Must be flagged. Severity stays
    critical.
  - >
    git subcommand allowlist with bypass via alias — `const SAFE = new
    Set(["log","status"]); if (SAFE.has(argv[0])) exec("git " + argv[0])`.
    The allowlist passes on argv[0] == "log", but git aliases (configured
    via `-c alias.log=...`) can map "log" to arbitrary commands. The
    charter acknowledges this as out-of-scope for static analysis and
    emits a medium-severity finding when an allowlist-check pattern is
    visible — the finding prompts the reviewer to audit the allowlist's
    contents and disable alias expansion.
  - >
    argv passed as array but elements concatenated from strings with user
    input — `spawn("git", ["clone", userUrl, "--branch", userBranch])`.
    The argv-array shape is what makes spawn "safe" for shell metachars,
    but when argv[2] is user-controlled and starts with `--`, it becomes
    an injected FLAG (not an injected SHELL metachar). The charter treats
    argv entries starting with `--` that originate from taint as a
    critical finding — this is exactly the CVE-2025-68145 pattern.
  - >
    Paths pointing at `.ssh` or `.git/config` directly — `git_init(pathArg)`
    where pathArg is user-controlled and could be `$HOME/.ssh` (the
    CVE-2025-68144 pattern) or `writeFile($HOME/.git/config, userContent)`
    (skipping git altogether). The charter detects both: the former via
    git_init taint tracking, the latter via write-file sink patterns
    with paths containing `.git/` or `.ssh/`.
  - >
    simple-git / nodegit library usage — `import simpleGit; simpleGit()
    .clone(userUrl)`. Library wrappers vary: some sanitise (simple-git
    rejects argument-looking values), some don't (nodegit passes through).
    The charter treats library usage as a positive signal (charter-
    sanitiser) but not a guaranteed mitigation — severity drops to
    informational, with the reviewer instructed to check the library's
    argument-validation layer.

edge_case_strategies:
  - git-c-override-is-critical                    # `-c key=value` overrides are exploit primitives
  - allowlist-bypass-via-alias-is-medium          # subcommand allowlist + alias escape
  - argv-array-with-tainted-flag-is-critical      # argv[] with user arg starting with `--` is CVE-2025-68145
  - ssh-dot-git-write-paths-are-critical          # writes to .ssh / .git/config paths
  - library-usage-is-informational                # simple-git / nodegit usage drops severity
  - ast-taint-interprocedural                     # source → exec / spawn of git across assignments
  - lightweight-taint-fallback                    # Python subprocess patterns via regex analyser

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
    - git_specific_sink_confirmed              # positive — the sink's argv[0] is "git"
    - unverified_sanitizer_identity
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Every MCP server that wraps git uses a validated library that rejects
    argument-looking arguments by default (simple-git 4.x + strictArgCheck
    flag is the current direction), AND the MCP spec mandates schema-level
    validation of path/ref arguments. Until both land, J2 stays critical.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
  - intermediate-variable
  - add-noop-conditional
mutations_acknowledged_blind:
  - rename-danger-symbol
---

# J2 — Git Argument Injection (Taint-Aware + Structural)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers whose tools wrap git operations. The primary
real-world precedent is Anthropic's own mcp-server-git (CVE-2025-68143
+ 68144 + 68145 chain).

## What an auditor accepts as evidence

A CVE-2025-68143-68145 auditor requires:

1. **Source** — a `source`-kind Location on the AST node where user
   input enters (tool parameter, req.body, process.argv).

2. **Sink** — the exec / spawn / subprocess call that has "git" as
   its argv[0]. The sink expression MUST preserve enough text to
   show either (a) a template literal including "git", or (b) an
   argv array whose first element is "git" and whose later elements
   are tainted. `sink_type = "command-execution"`,
   `cve_precedent = "CVE-2025-68143"`.

3. **Mitigation** — present iff a charter-audited git library
   (simple-git, nodegit, isomorphic-git) is on the path OR a validated
   argument allowlist is visible; absent otherwise.

4. **Impact** — `remote-code-execution`, scope `server-host`,
   exploitability `trivial` (the CVE chain demonstrated RCE with a
   single tool call).

5. **Verification steps** — inspect source, inspect git sink,
   trace the path, inspect sanitiser (if present).

## Why confidence is capped at 0.93

J2 is CVE-backed on a CVSS-9.1 chain in Anthropic's own MCP server —
the highest-precedence precedent the analyser has. The remaining 0.07
gap is reserved for:

- runtime argument-normalising libraries whose presence is not visible
  to static analysis;
- git versions that have patched specific flags (--upload-pack defaults
  changed in git 2.12).
