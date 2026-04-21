---
rule_id: K9
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-ASI04-agentic-supply-chain
    url: https://owasp.org/www-project-agentic-ai-top-10/
    summary: >
      OWASP Agentic AI Top 10 category ASI04 — Agentic Supply Chain
      Vulnerabilities. Dependency install hooks (npm postinstall / preinstall,
      Python setup.py cmdclass, pyproject.toml hooks) execute with the
      installing user's full privileges BEFORE any runtime scanning. Any
      network request or shell command in an install hook is a supply-chain
      RCE vector.
  - kind: paper
    id: MITRE-ATLAS-T0017-supply-chain-compromise
    url: https://atlas.mitre.org/techniques/AML.T0017
    summary: >
      MITRE ATLAS AML.T0017 Supply Chain Compromise. The ua-parser-js,
      event-stream, colors (October 2021 / November 2021 / March 2022),
      and PyTorch nightly (December 2022) incidents are the canonical
      real-world instances of this technique: a malicious package's
      postinstall script fetched and executed a payload during npm
      install, compromising every CI runner and developer machine.
  - kind: spec
    id: CoSAI-MCP-T6-supply-chain-integrity
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP Threat Taxonomy — T6 Missing Integrity / Verification. A
      dependency that executes code at install time bypasses every integrity
      check that inspects runtime behaviour, because the exploit fires
      during dependency resolution.
  - kind: spec
    id: CoSAI-MCP-T11-supply-chain-lifecycle
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      CoSAI MCP-T11 Supply Chain / Lifecycle Failures. Install-time code
      execution is an explicitly-enumerated lifecycle failure class; K9
      is the static detector for this T11 sub-category.

lethal_edge_cases:
  - >
    postinstall that only runs in a development `NODE_ENV` — `postinstall:
    "node -e \"if (process.env.NODE_ENV === 'dev') require('child_process').
    execSync('curl ...')\""`. A rule that examined the bare script text
    would still flag this, but the runtime behaviour is different: the
    payload only fires in dev environments. The charter treats the dev-
    gate as IRRELEVANT for severity — the pattern is still a supply-chain
    vector for any developer machine installing the package. Severity
    stays critical.
  - >
    postinstall that writes a file then does nothing — `postinstall:
    "echo 'hi' > /tmp/marker"`. This IS an install-time side effect but
    not a fetch-or-exec pattern. The charter treats file writes alone
    as Medium-risk (not critical): the install process is supposed to
    compile / write output. Severity for this pattern is downgraded.
  - >
    preinstall that calls a helper script from the SAME package — `preinstall:
    "node ./scripts/build.js"`. The helper lives inside the installed
    package, so a reviewer could inspect it. This is NOT a curl-pipe-sh
    pattern — trust boundary is different (the attacker already controls
    the package). The charter flags this at `high` severity only, and the
    evidence chain notes that the script lives in the package itself.
  - >
    Python setup.py cmdclass with `install` override calling subprocess —
    the cmdclass mechanism is the Python equivalent of npm postinstall.
    `class PostInstall(install): def run(self): subprocess.run([...])`.
    The lightweight taint analyser picks this up via the `subprocess.run`
    sink even when no HTTP source is present, because the Python setup.py
    context itself is the "source" (install time). The charter explicitly
    treats any subprocess / urllib / requests call inside a cmdclass
    override as a critical finding.
  - >
    `pyproject.toml` build-system backend pointing at a project-local
    module — the module's top-level code runs during install. This is
    the modern Python equivalent of setup.py's install hook. The charter
    recognises build-system.build-backend = "localmodule.build" as a
    high-severity indicator: local backends are legitimate (poetry,
    hatchling, setuptools) but a project-local backend with arbitrary
    top-level code is an install-time RCE vector.

edge_case_strategies:
  - dev-env-gate-does-not-mitigate              # NODE_ENV checks don't change severity
  - file-write-only-is-medium-severity          # echo-to-file without fetch/exec is not critical
  - project-local-helper-script-is-high         # relative-path helper stays high, not critical
  - setup-py-cmdclass-subprocess-is-critical    # Python setup.py install hooks = K9 critical
  - pyproject-local-backend-is-high             # build-backend pointing at project-local module
  - pipe-to-shell-pattern-is-critical           # curl|bash, wget|sh are canonical supply-chain attack
  - base64-decode-in-hook-is-critical           # obfuscated payload via Buffer.from / atob / base64

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - install_hook_location_identified         # which lifecycle hook (postinstall / preinstall / cmdclass)
    - dangerous_command_family                 # fetch-and-exec / inline-base64 / shell-invocation / subprocess
    - severity_adjustment                      # recorded when pattern warrants high/medium instead of critical
    - charter_confidence_cap                   # emitted when the 0.90 cap hits
  location_kinds:
    - source
    - config                                   # package.json / pyproject.toml pointer

obsolescence:
  retire_when: >
    npm adopts a default-on `--ignore-scripts` policy such that install
    hooks never execute by default, and Python removes setup.py install
    cmdclass as a legitimate extension point (PEP 517 build backends
    replacing it). Until both changes land, K9 remains critical.
---

# K9 — Dangerous Post-Install Hooks (Structural + Taint)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** Source inputs that include `package.json`, `setup.py`,
or `pyproject.toml` content — this rule's "source code" field is
typically the manifest text itself.

## What an auditor accepts as evidence

A MCP10 / ASI04 / MITRE T0017 auditor requires:

1. **Source** — a `config`-kind Location for `package.json` / `setup.py`
   / `pyproject.toml` install hooks, or a `source`-kind Location for
   Python install-class methods. The specific hook field
   (`scripts.postinstall`, `scripts.preinstall`, setup.py cmdclass
   entries) is reported on the `source.location.json_pointer`.

2. **Sink** — the dangerous command family detected inside the hook
   body. Categories: `fetch-and-exec` (curl | sh), `inline-base64`
   (Buffer.from / atob), `shell-invocation` (bash / sh / cmd.exe),
   `subprocess` (subprocess.call / subprocess.run / os.system inside
   cmdclass). `sink_type = "command-execution"`, `cve_precedent =
   "CWE-829"`.

3. **Mitigation** — present iff the hook is gated by a strict
   environment check that limits execution (e.g. a recognised build-
   only hook that calls tsc / node-gyp / prebuild without network).
   Mitigation drops severity.

4. **Impact** — `remote-code-execution`, scope `server-host`,
   exploitability `trivial` (the exploit fires at `npm install` time
   without user interaction beyond running the install command).

## Why confidence is capped at 0.90

Install-hook string analysis is structural, not AST — a clever
obfuscation (base64-inside-base64, runtime module-name resolution)
can evade detection. Capping at 0.90 leaves room for:

- obfuscation techniques that the charter's token list does not match;
- legitimate build hooks that use shell invocation for compilation
  (node-gyp, prebuild, esbuild, tsc — charter-audited names);
- CI-only scripts hidden behind environment variables.

The cap is visible as `charter_confidence_cap` on every finding that
would otherwise exceed it.
