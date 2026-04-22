---
rule_id: C12
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2017-5941
    url: https://nvd.nist.gov/vuln/detail/CVE-2017-5941
    summary: >
      node-serialize arbitrary code execution via crafted IIFE payload inside
      `unserialize()`. The canonical deserialisation→eval CVE — any npm MCP
      server that imports `node-serialize` and feeds it untrusted data is
      directly exploitable with the published PoC. Cited as C12's primary
      MCP-ecosystem precedent.
  - kind: spec
    id: OWASP-MCP05-privilege-escalation
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP05 — Privilege Escalation. Unsafe
      deserialisation of attacker-controlled input is the single largest
      privilege-escalation vector in the npm/PyPI ecosystems; when an MCP
      server deserialises data crossing the tool-argument surface, a
      payload crafted against pickle/yaml/node-serialize yields RCE on
      the server host. Cited as the controlling owasp_category.
  - kind: spec
    id: OWASP-ASI05-unexpected-code-execution
    url: https://owasp.org/www-project-agentic-ai-top-10/
    summary: >
      OWASP Agentic AI Top 10 category ASI05 — Unexpected Code Execution.
      Agentic applications often deserialise tool outputs or shared state
      using pickle/yaml.load; a malicious upstream agent can craft a
      payload that executes during deserialisation.
  - kind: spec
    id: CWE-502-deserialization-of-untrusted-data
    url: https://cwe.mitre.org/data/definitions/502.html
    summary: >
      CWE-502 Deserialization of Untrusted Data. The canonical weakness
      class: a deserialiser that executes embedded code during object
      reconstruction (pickle, yaml.load, node-serialize, marshal,
      ObjectInputStream, PHP unserialize).
  - kind: paper
    id: MITRE-ATLAS-T0054-LLM-prompt-injection
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054. When an AI agent fills a tool parameter with
      serialised data (e.g. a base64-encoded pickle blob) chosen by the
      attacker, the agent becomes the delivery mechanism for the RCE payload.

lethal_edge_cases:
  - >
    `yaml.load` with the `Loader=` keyword pointing at a custom Loader —
    `yaml.load(data, Loader=CustomLoader)`. A rule that only checks the
    literal call `yaml.load(` would miss that it's arguably safe if
    `CustomLoader` extends SafeLoader, or unsafe if it extends
    FullLoader/UnsafeLoader. The charter requires the finding to
    preserve the full sink expression (including the Loader keyword)
    on `sink.observed` so a reviewer can look up the Loader's class.
    Severity stays critical because — in real code — CustomLoader is
    almost never safer than SafeLoader.
  - >
    `pickle.loads` inside a `try/except` that re-raises — the exception
    handler does not neutralise the RCE; the code executes BEFORE the
    `except` runs. A rule that suppresses findings when the sink is
    inside a `try` would be wrong. The C12 charter explicitly treats
    `try/except` around deserialisation as irrelevant to the finding:
    the exploit fires at `pickle.loads` time, not at value-use time.
  - >
    User-controlled class resolution in a JSON reviver — `JSON.parse(
    userData, (k, v) => v.__class__ ? createInstance(v.__class__, v) :
    v)`. JSON itself is safe, but a reviver that instantiates classes
    from user-controlled `__class__` strings turns JSON.parse into a
    deserialiser. Out-of-scope for simple sink matching; the charter
    requires the finding to point at the reviver when the AST analyser
    sees a second argument to JSON.parse that references `__class__`.
    Falls back to manual review.
  - >
    Double deserialisation — JSON.parse produces a string that is then
    passed to pickle.loads. The first step (JSON.parse) is safe; the
    second (pickle.loads) is the sink. A rule that considered the flow
    "started with JSON.parse, so it's safe" would miss this chain. The
    AST taint analyser correctly reports the flow starting from the
    JSON.parse output and terminating at pickle.loads.
  - >
    Custom `unserialize()` wrapper — a project exports `unsafeUnserialize
    (data) { return require('node-serialize').unserialize(data); }` and
    calls THAT. A rule that only matched `node-serialize` by import
    would miss this. The AST analyser traces through one function call
    to the library's unserialize; the charter accepts this as an
    in-scope AST hop.

edge_case_strategies:
  - yaml-loader-keyword-preservation           # Loader=... argument stays on sink.observed
  - try-except-does-not-neutralise             # findings fire even when inside a try block
  - json-reviver-class-instantiation           # reviver with class-resolution falls back to manual review
  - multi-hop-deserialisation-chain            # JSON.parse → pickle.loads chain tracked by AST taint
  - custom-unserialize-wrapper-resolved        # AST taint follows one hop through a project wrapper
  - ast-taint-interprocedural                  # source→sink across assignments, parameters, returns
  - lightweight-taint-fallback                 # Python-heavy cases handled by regex-based analyser

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
    Every mainstream serialiser library exposes a default-safe API that
    refuses to construct arbitrary classes, and every legacy unsafe API
    (pickle.loads, yaml.load-without-Loader, node-serialize.unserialize)
    is removed from the core distribution. Python 3.14 deprecating
    pickle.loads with a runtime warning would be a significant step;
    removal would retire this rule.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# C12 — Unsafe Deserialization (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source code is available and which call a deserialiser that executes
embedded object-construction code (pickle, yaml.load without
SafeLoader, node-serialize, marshal, ObjectInputStream.readObject,
PHP unserialize).

## What an auditor accepts as evidence

A MCP05 / CWE-502 auditor will not accept "this server calls
pickle.loads". They require:

1. **Source** — a `source`-kind Location on the AST node where untrusted
   data enters. For MCP the most common surface is a tool parameter
   (`request.data`, `req.body.payload`, `event.arguments.data`).

2. **Propagation** — one link per AST hop. Single-hop flows (the source
   expression is the sink's first argument) have zero propagation links.

3. **Sink** — a `source`-kind Location on the deserialiser call. The
   sink expression text MUST include any `Loader=` / `fix_imports=` /
   reviver keyword so an auditor can see whether a SafeLoader was
   passed. `cve_precedent = "CVE-2017-5941"`, `sink_type =
   "deserialization"`.

4. **Mitigation** — present when a sanitiser (yaml.safe_load,
   ast.literal_eval, JSON.parse, charter-audited wrapper) is on the
   path; absent otherwise. Mitigation-present drops severity to
   informational per CHARTER edge case (sanitiser-identity bypass).

5. **Impact** — `remote-code-execution`, scope `server-host`,
   exploitability `trivial` on direct flows and `moderate` on multi-hop.

6. **Verification steps** — open the source, open the sink, trace the
   path, inspect the sanitiser (if present). Every step's target is a
   structured Location.

## Why confidence is capped at 0.92

AST-confirmed in-file deserialisation is the strongest static proof.
The 0.08 gap exists for:

- custom loaders whose safety depends on a subclass definition the
  static analyser cannot model;
- JSON revivers and class-resolution hooks the analyser doesn't parse
  structurally;
- cross-file wrappers where the deserialiser is one-more-hop away.

The cap is visible as `charter_confidence_cap` on every AST-confirmed
chain whose raw confidence exceeds it.
