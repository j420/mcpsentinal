---
rule_id: P6
interface_version: v2
severity: critical
owasp: MCP07-insecure-config
mitre: AML.T0054
risk_domain: container-runtime

threat_refs:
  - kind: cve
    id: CVE-2010-3856
    url: https://nvd.nist.gov/vuln/detail/CVE-2010-3856
  - kind: spec
    id: LD_PRELOAD-Wiki
    url: https://man7.org/linux/man-pages/man8/ld.so.8.html
    summary: >
      The ld.so(8) manual page documents LD_PRELOAD as "a list of
      additional, user-specified, ELF shared objects to be loaded
      before all others" — every libc function call can be intercepted
      by a preloaded object. The Linux dynamic linker warns against
      setuid and setgid programs honouring LD_PRELOAD, but CVE-2010-3856
      demonstrates that LD_AUDIT and crafted library paths can escape
      those protections. Any process that honours LD_PRELOAD is a
      potential hijack sink for an attacker who can write to the
      specified path.
  - kind: paper
    id: Linux-LD_PRELOAD-Rootkits
    url: https://www.sans.org/reading-room/whitepapers/linux/ld-preload-rootkits-33828
    summary: >
      SANS research on LD_PRELOAD rootkits documents the well-known
      "hook every syscall, log every keystroke, intercept every
      authentication" pattern. Any MCP server that sets LD_PRELOAD as
      configuration, modifies /etc/ld.so.preload, or calls dlopen with
      a variable path is architecturally open to this rootkit class.

lethal_edge_cases:
  - >
    /etc/ld.so.preload write — a Dockerfile RUN that echoes a library
    path into /etc/ld.so.preload affects every binary on the system,
    including sshd / kubelet / containerd. The rule MUST flag writes
    to this path independently of the LD_PRELOAD environment variable
    — both produce the same effect but through different mechanisms.
  - >
    systemd unit injection — `Environment=LD_PRELOAD=/tmp/evil.so` in
    a systemd unit file bakes the hijack into every spawn. A rule
    scanning only Dockerfile / compose misses unit files. The rule
    flags LD_PRELOAD as a key=value pair in EVERY file type that
    reaches the node (systemd unit files have .service or .socket
    extensions and live under /etc/systemd/).
  - >
    dlopen with variable path — `dlopen(userControlledPath, flags)`
    where the path is not hard-coded is a dynamic variant of the same
    primitive. A rule that only matches LD_PRELOAD literals misses
    this code-level form. Variable-path dlopen gets a lower weight
    (the exploit requires an attacker-controlled write path) but is
    still flagged.
  - >
    macOS DYLD_INSERT_LIBRARIES — the macOS equivalent of LD_PRELOAD.
    Rules that only check the Linux form miss MCP servers running on
    macOS developer workstations. Both variables must be in the data
    table.
  - >
    /proc/pid/mem write — direct memory-space injection into a running
    process. This is not the same primitive as LD_PRELOAD, but it is
    the same CATEGORY (shared-library / memory hijack) and is detected
    via the same rule because the impact and remediation are
    architecturally identical.

edge_case_strategies:
  - ld-so-preload-file-write-detection
  - systemd-unit-scanning
  - dlopen-variable-path-detection
  - macos-dyld-variant
  - proc-mem-write-inclusion

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: false
    impact: true
  required_factors:
    - hijack_variant
    - attack_scope
    - variable_path
  location_kinds:
    - source
    - config

obsolescence:
  retire_when: >
    Every MCP server runs under systemd-nspawn / gVisor / Kata with
    LD_PRELOAD sanitisation at the runtime level AND /etc/ld.so.preload
    is mounted read-only by default. Neither is standard yet; until
    both land, this rule remains front-line.

mutations_survived: []
mutations_acknowledged_blind: []
---

# P6 — LD_PRELOAD and Shared Library Hijacking

**Author:** Senior MCP Infrastructure Security Engineer persona.
**Applies to:** Dockerfiles, docker-compose YAML, systemd unit files,
shell launch scripts, TypeScript / JavaScript / Python / C source
files that set LD_PRELOAD, write to /etc/ld.so.preload, call dlopen
with a variable path, attach ptrace, or write to /proc/PID/mem.

## What an auditor accepts as evidence

A CVE-2010-3856 / SANS-LD_PRELOAD-Rootkits auditor wants:

1. **Scope proof** — specific file + line carrying the hijack variant
   with a `source`-kind Location. One finding per distinct variant.

2. **Gap proof** — the observed pattern loads an arbitrary shared
   library into another process's address space OR writes directly to
   that address space. The rule names which of the six variants
   matched (LD_PRELOAD env, /etc/ld.so.preload write, DYLD_INSERT_
   LIBRARIES, dlopen-variable-path, /proc/PID/mem, ptrace-attach).

3. **Impact statement** — concrete rootkit / keylogger scenario. The
   preloaded library intercepts every libc call in the target process,
   including PAM authentication (credential capture), TLS I/O (cleartext
   capture), and exec (command history manipulation).

## What the rule does NOT claim

- It does not verify whether the hijacking library path is attacker-
  controlled — if the path is a trusted system library (libssl, libc),
  the line is flagged but operators may confirm legitimate use.
- It does not audit the filesystem permissions on the hijack target
  — a path that is only writable by root is materially safer, but
  the analyzer cannot observe runtime filesystem state.

## Why confidence is capped at 0.85

The variants are unambiguous in source; the uncertainty is whether
the specified path is controlled by the attacker. Trusted-system
library paths (libssl.so hard-coded) are legitimate library links;
variable paths or /tmp / /dev/shm paths are hijack vectors. 0.85
preserves room for the hard-coded-trusted-library case.
