---
rule_id: C10
interface_version: v2
severity: critical

threat_refs:
  - kind: cve
    id: CVE-2019-10744
    url: https://nvd.nist.gov/vuln/detail/CVE-2019-10744
  - kind: cve
    id: CVE-2018-3721
    url: https://nvd.nist.gov/vuln/detail/CVE-2018-3721
  - kind: spec
    id: CWE-1321-prototype-pollution
    url: https://cwe.mitre.org/data/definitions/1321.html
    summary: >
      CWE-1321 "Improperly Controlled Modification of Object Prototype
      Attributes ('Prototype Pollution')". Applicable to JavaScript and
      any language where object property lookups follow a prototype
      chain. An attacker-controlled key of "__proto__", "constructor",
      or "prototype" merged into a plain object poisons Object.prototype
      globally for every object in the process.
  - kind: spec
    id: OWASP-MCP05-privilege-escalation
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 MCP05 — Privilege Escalation. Prototype pollution
      is a privilege-escalation surface: an agent that can poison the
      prototype of a shared object elevates from ordinary tool caller
      to arbitrary method interception, which typically cascades into
      command execution or auth bypass.

lethal_edge_cases:
  - >
    lodash.merge / lodash.mergeWith / lodash.defaultsDeep / lodash.set
    with user-controlled input. The classic CVE-2019-10744 surface. The
    rule must detect the call itself AND establish that the second-
    argument source is user-controlled — a `_.merge(config, defaults)`
    call with two constant-like arguments is not a finding, but
    `_.merge(config, req.body)` is.
  - >
    Object.assign({}, JSON.parse(req.body)). Equivalent to _.merge at
    the prototype-pollution level because Object.assign copies own
    properties including enumerable __proto__ / constructor, and
    JSON.parse can produce such keys. The rule flags the pattern when
    any argument after position 0 is user-controlled.
  - >
    Recursive merge via `{ ...spread }` inside a user-driven loop —
    `for (const key of Object.keys(userObj)) { target[key] = userObj[key]; }`
    or `target = { ...target, ...userObj }`. Depth-first property write
    via a dynamic key IS the classic pollution vector even without
    lodash.
  - >
    JSON.parse reviver writes to __proto__ — `JSON.parse(json, (k, v) =>
    { obj[k] = v; return v; })`. This is a less-discussed variant of
    CVE-2018-3721 (hoek) — the attacker controls both `k` and `v` via
    the JSON blob. The rule flags a tainted key write inside a JSON
    reviver callback.
  - >
    Dynamic property access with user-controlled key — `config[key] =
    value` where `key` comes from req.body / request.args. Without key
    validation this writes to whatever prototype chain slot the
    attacker names. The rule distinguishes this from a safe pattern
    (`if (Object.prototype.hasOwnProperty.call(allowed, key))` before
    the write).
  - >
    Map-to-Object conversion of user-provided Map — `const obj =
    Object.fromEntries(userMap)`. If the attacker can inject a
    __proto__ entry into `userMap` (e.g. via JSON.parse with reviver),
    Object.fromEntries will happily set Object.prototype via the
    entry's key.

edge_case_strategies:
  - lodash-merge-with-tainted-input
  - object-assign-with-tainted-arg
  - dynamic-property-write-tainted-key
  - json-parse-reviver-pollution
  - object-fromentries-user-map
  - hasownproperty-guard-present    # charter-audited mitigation

evidence_contract:
  minimum_chain:
    source: true
    propagation: false
    sink: true
    mitigation: true
    impact: true
  required_factors:
    - tainted_source_proximity
    - sink_function_identity
    - hasownproperty_guard_present
    - charter_confidence_cap
  location_kinds:
    - source

obsolescence:
  retire_when: >
    Node.js v24+ turns on Object.prototype freezing by default AND the
    ecosystem no longer exposes lodash.merge-style APIs that accept
    untrusted input — OR all agent configuration objects are created
    with Object.create(null) by the MCP SDK. Until either, C10 retains
    critical severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - reorder-object-properties
mutations_acknowledged_blind: []
---

# C10 — Prototype Pollution (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers in TypeScript or JavaScript source whose
configuration, request-handling, or tool-argument parsing merges
external data into plain objects.

## What an auditor accepts as evidence

A CWE-1321 / CVE-2019-10744 auditor will not accept "a file contains
__proto__". They accept a structured chain showing:

1. **Source** — a source-kind Location on the AST node where
   untrusted data enters (HTTP body/params/query, MCP tool
   argument, JSON.parse of external string, process.env for
   config-merge scenarios).

2. **Sink** — a source-kind Location on one of:
   (a) a merge function call: `_.merge`, `_.mergeWith`,
   `_.defaultsDeep`, `_.set`, `Object.assign`, `deepmerge`,
   `merge-deep`, `deep-extend`, `Object.fromEntries`;
   (b) a dynamic property write: `obj[dynamicKey] = value` where
   `dynamicKey` comes from user input;
   (c) an explicit `obj.__proto__` / `obj.constructor.prototype`
   write.
   The sink_type on the chain is `code-evaluation` — prototype
   pollution's impact is code execution via the poisoned prototype.

3. **Mitigation** — the chain records whether the sink is guarded by
   a `hasOwnProperty`, `Object.create(null)`, `Object.freeze`, a key
   allowlist, or a structured-clone round-trip. Absence of any
   guard on the flow keeps severity at critical; presence drops it
   to informational with a charter-audited check.

4. **Impact** — `privilege-escalation`, scope `server-host`.
   Poisoning `Object.prototype.isAdmin = true` changes every object
   in the process. Poisoning `Object.prototype.shell` combined with
   a child_process call elsewhere reaches RCE via CVE-2019-10744.

5. **Verification steps** — one per flow node + a dedicated step for
   the guard (or its absence).

## What the rule does NOT claim

- It does not prove runtime reachability across module boundaries.
  A prototype-pollution vector inside an unreachable branch may still
  fire because static analysis cannot prove unreachability.
- It does not flag `Object.create(null)` targets — those cannot be
  polluted by design. The charter notes the guard explicitly.

## Why confidence is capped at 0.92

AST-confirmed in-file taint into a recognised pollution sink is the
strongest static proof. The 0.08 gap is for:

- Map-of-Map structures where the AST analyser cannot prove that a
  top-level key is user-controlled;
- proxied `obj[key] = value` writes wrapped in a library validator;
- Node.js / V8 runtime flags that disable prototype mutation
  (`--disallow-prototype-mutation`), which the static analyser cannot
  observe.

The cap surfaces as a `charter_confidence_cap` factor on every
AST-confirmed chain whose raw confidence exceeds it.
