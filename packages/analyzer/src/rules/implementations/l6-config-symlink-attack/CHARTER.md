---
rule_id: L6
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-53109
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53109
  - kind: cve
    id: CVE-2025-53110
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-53110
  - kind: paper
    id: Cymulate-EscapeRoute-2025
    url: https://cymulate.com/blog/escape-route-mcp-filesystem-boundary-bypass
    summary: >
      Cymulate EscapeRoute research demonstrating that MCP filesystem servers
      whose root-containment check uses startsWith() on a user-resolved
      path — without a realpath() / lstat() pre-check — are bypassable via
      a symlink whose target resolves outside the declared root. The
      symlink itself lives inside the root, satisfying startsWith, while
      reading the linked target reads /etc/passwd, ~/.ssh, or similar.

lethal_edge_cases:
  - >
    Symlink-to-/etc/passwd via TOCTOU race — the server calls lstat() on
    a user-supplied path, sees that it is NOT a symlink, then calls
    readFile() on the same path. Between the two calls, an attacker
    races to replace the regular file with a symlink pointing at
    /etc/passwd. A rule that accepts "lstat present" as a mitigation
    misses this; the rule must require fstat() on an already-opened
    file descriptor (AtomicOpen pattern) to count as mitigated.
  - >
    Bind-mount resolving outside chroot — the server container
    bind-mounts /host/.ssh into /sandbox/.ssh for "user convenience".
    The realpath() check inside the container resolves /sandbox/.ssh,
    which looks safe, but the underlying bytes are outside the chroot
    boundary. The rule flags any bind-mount / volume mount of
    host-credential directories into the workload; no realpath check
    inside the container can undo a bind-mount.
  - >
    Windows junction-point bypass — on Windows, junction points look
    like directory symlinks but are created with mklink /J and are
    invisible to POSIX lstat(). If the rule only checks for
    fs.lstatSync().isSymbolicLink() it misses junctions. The rule
    must also flag code paths that resolve Windows file paths without
    calling fs.realpathSync.native(), which is the only POSIX-aware
    resolver on Windows.
  - >
    startsWith-based containment — code does
    `if (resolvedPath.startsWith(rootDir)) { readFile(resolvedPath) }`.
    The intent is a directory boundary check; the defect is that
    resolvedPath has already been symlink-resolved via path.resolve()
    (which does NOT follow symlinks), so a symlink inside rootDir whose
    target is outside rootDir still passes startsWith. This is the
    CVE-2025-53109 class.
  - >
    Symlink CREATION to a sensitive path — the server writes a symlink
    into an attacker-controllable config directory (e.g., .claude/,
    .cursor/mcp.json), pointing the link at /etc/sudoers. When a
    privileged downstream tool reads the config, it reads /etc/sudoers.
    This is the inverse of the read path and the rule flags fs.symlink*
    calls whose target is a sensitive system path.

edge_case_strategies:
  - symlink-creation-sensitive-target
  - path-resolve-without-realpath
  - lstat-followed-by-read-race
  - no-nofollow-flag-on-open
  - symlink-lookup-in-config-dir

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - symlink-creation-to-sensitive-path
    - no-symlink-guard-before-read
    - no-nofollow-on-open
  location_kinds:
    - source

obsolescence:
  retire_when: >
    The Node.js standard library's fs.readFile / fs.open / fs.stat APIs
    default to O_NOFOLLOW (refusing to traverse symlinks unless
    explicitly allowed), OR MCP filesystem servers universally adopt
    the io_uring openat2() with RESOLVE_NO_SYMLINKS flag — at which
    point static analysis of Node fs calls no longer covers the
    remaining risk surface.
---

# L6 — Config Directory Symlink Attack

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP server source that performs filesystem operations
on user-supplied paths, OR that creates symlinks into configuration
directories.

## Distinct from C2 (path traversal)

C2 detects `../` sequences in source-code patterns. L6 detects the
STRUCTURAL mismatch between a symlink-aware threat model and symlink-
unaware Node/Python filesystem code. Two attack shapes:

1. **Read-side** — server follows a symlink placed by an attacker and
   reads a file outside the declared root. Evidence: a file-read call
   whose target derives from user input AND is not preceded by both
   realpath() resolution and a root-containment check against the
   realpath result.

2. **Write-side** — server creates a symlink whose target is a
   sensitive system path. Evidence: a `fs.symlink` / `fs.symlinkSync` /
   `os.symlink` call whose second argument (the link path) is in an
   attacker-reachable directory and whose first argument (the target)
   hits the sensitive-path vocabulary.

## What an auditor accepts as evidence

1. **Source** — a `source`-kind Location at the offending `fs.symlink*`
   or `fs.readFile*` / `fs.open` / `fs.createReadStream` call.
2. **Classification** — the finding's factors state which family
   fired: symlink-creation-to-sensitive-path (write-side),
   no-symlink-guard-before-read (read-side), or no-nofollow-on-open
   (read-side with fd API).
3. **Mitigation** — whether a realpath / realpathSync / lstat.isSymbolicLink /
   O_NOFOLLOW / AT_SYMLINK_NOFOLLOW / io.open with O_NOFOLLOW appears
   in the same function scope. Present → severity degraded; absent →
   finding escalated.
4. **Impact** — named CVE precedent (CVE-2025-53109 / 53110) and the
   concrete scenario (read arbitrary system file OR poison downstream
   agent config).

## Why confidence is capped at 0.85

Node's fs APIs differ in their default symlink-following behaviour;
without full control-flow analysis the rule may miss an AT_SYMLINK_NOFOLLOW
equivalent expressed via a helper abstraction. The 0.85 cap holds room
for that category of defensive code.
