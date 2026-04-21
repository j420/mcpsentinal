---
rule_id: C13
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-MCP03-ssti
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP03 — Command/Template Injection. Covers
      user-controlled strings passed as the template itself (not as template
      variables) to Jinja2, Mako, Handlebars, EJS, Pug, Nunjucks, Twig, or
      similar. Cited as the controlling owasp_category.
  - kind: spec
    id: OWASP-ASI05-unexpected-code-execution
    url: https://owasp.org/www-project-agentic-ai-top-10/
    summary: >
      OWASP Agentic AI Top 10 category ASI05 — Unexpected Code Execution.
      Server-side template engines run as sandboxed interpreters but most
      Jinja2 / Nunjucks / EJS configurations grant enough primitives to
      break out (attribute access, python-module traversal, object
      reconstruction). A server that compiles an attacker-controlled string
      as a template gives the attacker an interpreter.
  - kind: spec
    id: CWE-1336-ssti
    url: https://cwe.mitre.org/data/definitions/1336.html
    summary: >
      CWE-1336 Improper Neutralization of Special Elements Used in a Template
      Engine. The canonical weakness class: template strings built from user
      input allow expression evaluation that can escape the template sandbox.
  - kind: paper
    id: Portswigger-SSTI-Research
    url: https://portswigger.net/research/server-side-template-injection
    summary: >
      Portswigger's SSTI research by James Kettle (2015). Establishes the
      canonical payload families (Jinja2 {{7*7}}, Mako ${7*7}, Handlebars
      {{#with "s" as |string|}}) and the classification of template engines
      by exploit primitive richness. Still the definitive reference for
      "is this engine exploitable from a raw template string?".

lethal_edge_cases:
  - >
    Template compiled from concatenation where one side is trusted literal —
    `Handlebars.compile("Hello " + userName)`. The first-part being a
    constant does NOT make the whole expression safe; the second-part is
    still a user-controlled template string whose contents will be compiled
    as template syntax. The AST taint analyser correctly flags the concat
    result as tainted.
  - >
    Template-engine wrapper that auto-escapes — `ejs.render(userTpl, data,
    { escape: true })`. Auto-escape affects VARIABLE INTERPOLATION within
    an already-compiled template; it does not stop the compiler from
    executing expressions in the template source string itself. The
    finding must still fire because the exploit is in the template syntax,
    not in the data. Severity stays critical.
  - >
    Compile-time vs render-time user input — `const tpl = Handlebars.compile
    (STATIC_STRING); tpl({ message: req.body.msg })`. Compile time is
    safe (the template is a literal); only runtime data is user-controlled,
    and it flows only through the safe variable-interpolation path. A rule
    keyed on `Handlebars.compile(` would false-positive if it did not
    distinguish the argument's origin. The AST taint analyser must see a
    literal as the compile argument and skip the finding.
  - >
    `res.render` with a file path — `res.render(userTpl)` where `userTpl`
    is a filename. Express's render takes a TEMPLATE NAME, not a template
    string; the file is loaded from disk. The finding must NOT fire for
    express-style `res.render` because the file-load path is a different
    risk class (path traversal, not SSTI). The taint analyser's sink
    taxonomy distinguishes `template_injection` from file path access.
  - >
    Jinja2 `Environment().from_string(user_input)` — from_string takes a
    raw template string and MUST be flagged. A rule keyed only on
    `jinja2.Template(` would miss this because `from_string` is the
    idiomatic way to compile a string template in Jinja2.

edge_case_strategies:
  - compile-time-vs-runtime-data               # literal-source compile is safe; variable-source compile fires
  - concat-partial-literal-still-tainted       # constant-prefix does not neutralise a template source
  - autoescape-does-not-mitigate-source        # autoescape is a runtime control on data, not on template source
  - file-path-render-is-different-risk         # res.render(name) is not SSTI
  - jinja-from-string-flagged                  # Environment().from_string(x) is a sink under the same taint chain
  - ast-taint-interprocedural                  # source → compile / render sink across assignments
  - lightweight-taint-fallback                 # Python jinja2 patterns handled by the regex analyser

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
    Template engines remove the expression-evaluation primitive at compile
    time when the template source is not attested. Jinja2 default-SandboxedEnvironment
    and Handlebars helpers-only mode would be acceptable paths. Until every
    mainstream engine requires an explicit "I trust this string" flag, C13
    stays active.
---

# C13 — Server-Side Template Injection (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers that compile templates from user-controlled
strings using Jinja2, Mako, Handlebars, EJS, Pug, Nunjucks, Twig, or
similar engines.

## What an auditor accepts as evidence

A MCP03 / CWE-1336 auditor will not accept "this server uses Handlebars".
They require structured evidence:

1. **Source** — a `source`-kind Location on the AST node where the
   template string originates from user input.

2. **Propagation** — hops from source to sink. Often 0 hops (direct
   template compilation of the user string).

3. **Sink** — the compile / render / from_string call. Sink expression
   MUST preserve enough text to disambiguate safe render-from-file
   vs unsafe compile-from-string patterns. `sink_type = "template-render"`,
   `cve_precedent = "CWE-1336"`.

4. **Mitigation** — present iff a charter-audited escaper / sandbox
   (`SandboxedEnvironment`, `autoescape: true` as a compile-time flag,
   `allowProtoPropertiesByDefault: false`) is on the path; absent
   otherwise. Mitigation does NOT change severity here — the charter
   explicitly rejects "autoescape mitigates SSTI"; autoescape protects
   data, not the template source.

5. **Impact** — `remote-code-execution`, scope `server-host`,
   exploitability `trivial` on direct template compilation.

## Why confidence is capped at 0.92

Template-engine sandboxing varies. The gap leaves room for:

- runtime SandboxedEnvironment that the static analyser cannot detect
  by configuration alone;
- Helpers-only Handlebars configurations that restrict compile-time
  expressions;
- Wrapper libraries (fastify-view, eta with strict mode) whose safety
  depends on runtime flags the analyser cannot see.
