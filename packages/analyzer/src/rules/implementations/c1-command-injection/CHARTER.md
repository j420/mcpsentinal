---
rule_id: C1
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2025-6514
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-6514
    summary: >
      mcp-remote — OS command injection in the MCP remote bridge (CVSS 9.6,
      June 2025). A tool parameter flowed through `child_process.exec()`
      without sanitisation, giving an attacker remote code execution on the
      server host by crafting a malicious tool invocation. Canonical real-
      world instance of the `user-parameter → exec` pattern this rule detects.
  - kind: cve
    id: CVE-2025-68143
    url: https://nvd.nist.gov/vuln/detail/CVE-2025-68143
    summary: >
      Anthropic `mcp-server-git` — argument injection chain (October 2025).
      Part of a three-CVE chain with 68144 and 68145: unvalidated path
      argument → `git_init` on `.ssh` → malicious `.git/config` →
      RCE via `core.sshCommand`. Demonstrates why a rule that only checked
      for `exec(varname)` would miss the higher-level vulnerability when
      execution happens through a structured argv to git.
  - kind: cve
    id: CVE-2017-5941
    url: https://nvd.nist.gov/vuln/detail/CVE-2017-5941
    summary: >
      `node-serialize` arbitrary code execution via crafted IIFE payload
      during `unserialize()`. Kept in the charter as the archetypal
      "deserialisation → eval" instance of the same command-injection
      family — demonstrates why `eval` and `new Function()` have to be
      treated as command-execution sinks under rule C1, not a separate
      category (deserialisation-only rules miss the `exec` surface).
  - kind: spec
    id: OWASP-MCP03-command-injection
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP03 — Command Injection. Covers untrusted
      tool arguments reaching a shell/subprocess call on the MCP server host.
      Charter-mapped to this rule so that the finding's `owasp_category`
      field is the controlling reference used by every compliance agent.
  - kind: spec
    id: CoSAI-MCP-T3
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP Threat Taxonomy — T3 Unsafe Code Execution. Enumerates
      `exec`, `spawn(..., {shell: true})`, `os.system`, `subprocess.*(shell=True)`,
      `eval`, `new Function()`, and VM-module entry points as the sinks an
      MCP scanner must treat as dangerous. This rule's sink lexicon is the
      engineering mirror of T3.
  - kind: paper
    id: MAESTRO-L1-Foundation
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 1 (Foundation) — Unsafe Code Execution. Establishes that
      an agent which can reach a system shell from an LLM-controlled string
      is, by construction, a bypass of every downstream control. Used as
      the threat-model rationale for setting severity=critical on every
      unsanitised source→sink C1 flow.

lethal_edge_cases:
  - >
    Interprocedural beyond a single file — `handler(input)` is exported from
    `routes.ts` but the call `exec(input)` lives in `cli.ts`. An
    in-file-only taint analyzer sees only `exec(input)` (no recognised
    source) in `cli.ts` and declares it safe. The rule must degrade to
    regex-with-variable fallback (severity high, not critical) rather than
    silently dropping the finding.
  - >
    Sanitizer-identity bypass — the code contains
    `const safe = escapeShell(req.body.cmd); exec(safe);` but `escapeShell`
    is a user-defined function that returns its input unchanged. A
    sanitizer-by-name rule whitelists the call and suppresses the finding,
    even though nothing has actually been sanitised. The rule must emit
    severity `informational` (not nothing) so the sanitizer is still
    visible in the audit trail and a reviewer can inspect the definition.
  - >
    Constant-prefix template literal — `exec(\`git \${req.body.arg}\`)` is
    *not* safe just because the first token is a hardcoded `git`. The arg
    can contain `; rm -rf ~` and survive the shell word boundary. A rule
    that dismisses template literals whose prefix is a static string
    alongside git/ls/echo would miss CVE-2025-68143's class. Template
    literals with any non-literal substitution must be treated as tainted
    sinks.
  - >
    Python `shell=True` via variable — `subprocess.run(f"cmd {user}",
    shell=shell_mode)` where `shell_mode` resolves to True at runtime. A
    rule that only matches the literal `shell=True` misses this. The charter
    acknowledges this as out-of-scope for the TypeScript AST taint analyser
    and requires the regex fallback to flag the literal `shell=True` case
    (severity high) while documenting the gap for Phase 2.
  - >
    Destructured rename masking taint — `const { body: payload } = req;
    exec(payload.cmd);` (or an equivalent Python tuple unpack). A naive
    rule keyed on the identifier `req.body.cmd` sees nothing recognisable.
    The AST taint analyser must follow `req` through the destructuring
    rename to the new binding name `payload` before the sink check, or the
    finding silently disappears.

edge_case_strategies:
  - ast-taint-interprocedural     # trace source through assignment / param / return / destructure
  - sanitizer-verified-by-name    # presence of sanitizer drops severity to informational, does not drop the finding
  - template-literal-taint        # any non-literal substitution in a template inside an exec/eval sink is tainted
  - shell-true-argument-taint     # spawn/subprocess with shell:true + variable arg = sink
  - binding-alias-resolution      # destructured/renamed bindings must be followed, not string-matched
  - regex-fallback-degradation    # when AST taint cannot run (syntax failure or interprocedural miss), emit a severity-high finding with a negative "regex_only" confidence factor — never drop silently

evidence_contract:
  minimum_chain:
    source: true              # where the untrusted value enters (req.body, process.env, ...)
    propagation: false        # optional — AST flows present it; direct one-line sinks do not
    sink: true                # exec / spawn / eval / new Function / vm.run*
    mitigation: true          # must state whether a sanitiser is on the path, present=true/false
    impact: true              # must describe the RCE scenario in concrete terms
  required_factors:
    - ast_confirmed            # emitted when taint analyser confirmed the flow
    - interprocedural_hops     # how many AST propagation steps lie between source and sink
    - sanitizer_present        # true/false — determines severity
    - regex_fallback_only      # emitted (with negative adjustment) when no taint analyser confirmed
  location_kinds:
    - source                   # file:line:col for source, sink, sanitiser, and every propagation step
    - parameter                # tool parameter path when the taint source is an MCP tool argument
    - schema                   # JSON pointer into `input_schema` when the taint enters via an MCP tool parameter
    - dependency               # `npm:shelljs@*` when the sink is exposed via a dependency rather than core APIs

obsolescence:
  retire_when: >
    The Node.js and Python runtimes deprecate string-form `exec()` and
    `subprocess.run(shell=True)` such that passing an unvalidated
    concatenated string becomes a type error at module load — OR every
    MCP SDK release mandates argv-form `execFile()` wrappers verified at
    the protocol layer so no user-controlled string can reach a shell.
    Until one of those holds, C1 stays active at critical severity.

mutations_survived: []
mutations_acknowledged_blind: []
---

# C1 — Command Injection (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers in TypeScript, JavaScript, or Python that
register request or tool handlers and whose source code is available.

## What an auditor accepts as evidence

An OWASP MCP03 / CoSAI MCP-T3 auditor will not accept the claim
"this server uses `exec()`". They will accept a finding that shows,
structurally:

1. **Source** — a `source` Location on the AST node where untrusted data
   enters. For an HTTP handler this is the node for `req.body.X` /
   `req.query.Y` / `req.params.Z`; for a CLI entry this is `process.argv[n]`;
   for a config-driven handler this is `process.env.NAME`. The Location
   points at `file:line:col` so the reviewer can jump straight to the node.

2. **Propagation** — one `propagation` link per AST step between source
   and sink (assignment, destructure, template embed, return value,
   parameter binding, callback argument). Single-hop flows have zero
   propagation links and a one-line narrative; multi-hop flows record
   every hop so the reviewer can dispute any single step.

3. **Sink** — a `sink` Location on the `exec` / `execSync` / `spawn` /
   `spawnSync` / `eval` / `new Function(...)` / `vm.run*` / `shell.exec`
   call, with `cve_precedent` pointing at CVE-2025-6514 (primary) or
   CVE-2025-68143 (argv-form chain). The sink category is
   `command-execution` except for `eval`/`Function`/`vm.run*` which use
   `code-evaluation`.

4. **Mitigation** — always present, with `present: true` when a sanitiser
   lies on the path (named `escapeShell`, `shell-escape`, `shlex.quote`,
   etc.) and `present: false` otherwise. A sanitiser's presence drops
   severity to `informational` and the rule notes that the reviewer should
   inspect the sanitiser's definition (edge case 2: sanitizer-identity
   bypass).

5. **Impact** — a `remote-code-execution` impact link scoped to
   `server-host` with exploitability derived from the path length
   (single-hop = `trivial`, multi-hop = `moderate`).

6. **Verification steps** — one step per distinct AST hop, each carrying
   a source-kind Location. An auditor can open each target, read the line,
   and confirm the flow without re-running the scanner.

## What the rule does NOT claim

- It does not claim that every `exec()` call is a finding. `exec("git status")`
  with a hardcoded string, `execFile` with an argv array, and
  `subprocess.run([...], shell=False)` all produce zero findings.
- It does not claim the sanitiser actually sanitises — only that one is on
  the path. Edge case 2 (sanitizer-identity bypass) is expected to produce
  an `informational` finding that flags the sanitiser for review.
- It does not attempt cross-file interprocedural taint. When the source is
  in one file and the sink is in another, the rule degrades to regex
  fallback with a negative `regex_only` confidence factor rather than
  overclaiming.
- It does not model Python AST taint; Python patterns are caught by the
  regex fallback only (documented limitation).

## Why confidence is capped at 0.95

AST-confirmed, in-file, unsanitised source→sink is the strongest static
proof attainable for command injection. The 0.05 gap to 1.00 is reserved
for runtime configurations the static analyser cannot see:

- a downstream argv-normaliser library (e.g. `shell-escape`) applied at
  the process boundary;
- a container-level `NoNewPrivileges` / `seccomp` profile that constrains
  what a successful exec can do;
- an MCP gateway that whitelists the argv before forwarding.

The cap at 0.95 leaves room for that uncertainty rather than overclaiming.
Regex-fallback findings carry their own negative factor and never pass
the 0.70 threshold downstream scorers apply for confidence-weighted
penalties.
