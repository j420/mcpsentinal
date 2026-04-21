---
rule_id: C16
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-MCP03-command-injection
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP03 — Command / Code Injection. Covers
      user-controlled strings reaching eval / new Function / setTimeout(string)
      / vm.runInNewContext / importlib.import_module / __import__. Cited as
      the controlling owasp_category.
  - kind: spec
    id: OWASP-ASI05-unexpected-code-execution
    url: https://owasp.org/www-project-agentic-ai-top-10/
    summary: >
      OWASP Agentic AI Top 10 category ASI05 — Unexpected Code Execution.
      The agent-controlled parameter filling surface is the exact input
      vector modern attacks abuse: the LLM produces a string, the server
      passes it to eval, and the LLM's output becomes execution. This rule
      is the static complement to ASI05's dynamic runtime controls.
  - kind: spec
    id: CWE-95-eval-injection
    url: https://cwe.mitre.org/data/definitions/95.html
    summary: >
      CWE-95 Improper Neutralization of Directives in Dynamically Evaluated
      Code (Eval Injection). The canonical weakness class: user-controlled
      strings reaching a language-native expression evaluator.
  - kind: paper
    id: MITRE-ATLAS-T0054-LLM-prompt-injection
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 LLM Prompt Injection. When the LLM's output is
      passed to eval, the agent becomes the delivery mechanism for RCE — a
      prompt-injection-induced code-evaluation chain.

lethal_edge_cases:
  - >
    eval inside a try/catch that swallows errors — the catch does NOT
    prevent the code from executing; the exploit fires BEFORE the catch
    sees the exception (if the payload completes without throwing, no
    exception is even thrown). A rule that suppressed eval findings when
    wrapped in try/catch would be wrong. Evidence strength is UNCHANGED
    by the presence of a try/catch.
  - >
    Function constructor via bind — `Function.prototype.bind.call(
    Function, null, userCode)()`. A rule that only matched `new Function(`
    would miss this reflection-style construction. Out-of-scope for the
    AST analyser's direct sink detection; the charter accepts this as a
    known gap and notes the regex fallback in analyzeTaint should catch
    the `new Function` identifier if the payload lands elsewhere.
  - >
    `setTimeout` / `setInterval` with a string built from a backtick
    template — `setTimeout(\`doThing(\${userArg})\`, 100)`. These are
    explicitly eval-family in Node.js: the string argument is parsed and
    executed as code. The AST analyser's sink lexicon covers the
    identifier setTimeout/setInterval only when the first argument is
    a string, not a function literal.
  - >
    `vm.runInNewContext(userCode, sandbox)` — the "sandbox" argument is
    a plain object, not a security boundary. vm.runInNewContext is NOT
    a safe alternative to eval; it just runs in a freshly-created V8
    context. The charter explicitly treats vm.run* as code_eval sinks,
    not mitigations. Only a properly-configured isolated-vm / Node
    Worker with no `require` access would qualify, and the AST analyser
    cannot distinguish those at compile time.
  - >
    `importlib.import_module(user_name)` / `__import__(user_name)` in
    Python — loading arbitrary modules is code execution. A module's
    top-level body runs on import. The lightweight taint analyser is
    the primary detector for Python patterns; the AST analyser does not
    cover Python natively.

edge_case_strategies:
  - try-catch-does-not-mitigate-eval            # eval findings fire regardless of surrounding try/catch
  - function-constructor-reflection-out-of-scope # documented limitation; regex fallback where possible
  - setTimeout-string-argument-taint            # setTimeout(str) treated identically to eval(str)
  - vm-runInNewContext-is-a-sink                # "sandbox" argument is not a mitigation
  - python-importlib-via-lightweight            # lightweight analyser handles importlib / __import__
  - ast-taint-interprocedural                   # source → eval-family sink across assignments
  - lightweight-taint-fallback                  # Python-heavy cases

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
    JavaScript runtimes deprecate string-argument eval / Function / setTimeout
    at the engine level (an opt-out flag that causes a runtime error when
    those APIs receive a string), and Python removes the __import__ /
    importlib.import_module surfaces from its default interpreter. Neither
    is plausible before C16 matters most — the rule stays critical.
---

# C16 — Dynamic Code Evaluation with User Input (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers that pass user-controlled strings to eval /
new Function / setTimeout(string) / vm.run* / importlib.import_module /
__import__.

## What an auditor accepts as evidence

A MCP03 / ASI05 / CWE-95 auditor requires:

1. **Source** — a `source`-kind Location on the AST node of the
   untrusted value. For MCP this is a tool argument, `req.body.*`,
   or `process.env.*`.

2. **Propagation** — hops from source to sink. Often 0 hops because
   eval-family sinks accept strings directly.

3. **Sink** — the eval / new Function / setTimeout(string) / vm.run* /
   import_module call. `sink_type = "code-evaluation"`,
   `cve_precedent = "CWE-95"`.

4. **Mitigation** — present iff a charter-audited safe-parse function
   (JSON.parse, ast.literal_eval, a named allowlist check) lies on the
   path; absent otherwise. Mitigation drops severity to informational.

5. **Impact** — `remote-code-execution`, scope `server-host`,
   exploitability `trivial` on direct flows.

## Why confidence is capped at 0.92

Direct source→eval is the single strongest evidence class in the
analyser. The 0.08 gap exists for:

- vm.runInNewContext with a properly-locked-down sandbox (isolated-vm,
  Worker with no `require`) that the analyser cannot detect from
  signature alone;
- a project-local `safeEval` wrapper whose implementation must be
  audited by hand.
