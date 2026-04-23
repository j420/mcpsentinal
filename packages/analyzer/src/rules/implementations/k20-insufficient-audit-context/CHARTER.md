---
rule_id: K20
interface_version: v2
severity: medium

threat_refs:
  - kind: spec
    id: ISO-27001-A.8.15
    url: https://www.iso.org/standard/82875.html
    summary: >
      Event logs recording user activities, exceptions, faults, and
      information security events shall be produced, stored, protected, and
      analysed. A.8.15 is unambiguous that "analysed" presumes structure:
      an analyst must be able to correlate events across services by a
      shared identifier, attribute events to a caller, and reconstruct the
      order of operations. A log record that reduces to `logger.info("tool
      invoked")` — with no correlation id, no caller identity, no
      timestamp schema, no outcome field — is produced and stored but
      cannot be analysed. It is a failed audit record masquerading as
      compliance evidence.
  - kind: spec
    id: ISO-42001-A.8.1
    url: https://www.iso.org/standard/81230.html
    summary: >
      ISO/IEC 42001:2023 Annex A.8.1 — Documented information for AI system
      operation. Requires that the AI management system produce records
      sufficient to demonstrate observable, explainable behaviour of the
      AI system to stakeholders. For an MCP server whose handlers are the
      surface where the AI agent interacts with the world, a log record
      missing the tool name or caller identity fails the observability
      requirement because the record cannot be tied to a specific agent
      action.
  - kind: paper
    id: MAESTRO-L5-Observability
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO Layer 5 (Evaluation & Observability) mandates that every
      agent action be reconstructible from the logs alone, across service
      boundaries, without access to in-memory process state. The only way
      a downstream SIEM can join a log line from agent A to a log line
      from agent B is via a propagated correlation identifier; without it,
      the multi-agent timeline is unrecoverable. A log call that emits a
      bare string message is the archetype of what MAESTRO L5 calls a
      "dark" audit record.
  - kind: paper
    id: Mandiant-2024-M-Trends-Log-Gaps
    url: https://www.mandiant.com/m-trends
    summary: >
      Mandiant M-Trends 2024 reported that incomplete log fields — missing
      user identity, missing request id, missing outcome — were a primary
      root cause for prolonged dwell time in 23% of the breaches the
      responders investigated. The breach record exists but cannot be
      joined to surrounding telemetry, so the timeline is unrecoverable
      until weeks of manual correlation. This is the concrete operational
      cost of the compliance gap K20 names.

lethal_edge_cases:
  - >
    Outer-context spread — the log call is written as
    `logger.info({ ...ctx, msg: "tool call" })` where `ctx` is a higher-
    scope variable carrying the correlation id and caller identity. At
    the call site, the object literal observably contains only `msg`
    and a spread. A static rule that inspects only the literal property
    names sees one field and fires a false positive. The rule must
    recognise SpreadAssignment as an "opaque context" signal that
    defuses the emptiness verdict — the fields are present in a way
    the static analyser cannot enumerate, and the correct behaviour is
    silence, not a finding, with a PRESENT mitigation recording the
    ambiguity.
  - >
    Bindings-attached fields — pino's `logger.child({ correlation_id,
    tool }).info({ user_id, outcome }, "handled")` attaches fields via
    the child() bindings at logger-construction time, not at the call
    site. A rule that inspects only the immediate info() argument sees
    `{ user_id, outcome }` and may conclude fields 1 and 3 are missing.
    The rule must walk the receiver expression: when the call receiver
    is a `child(<obj>)` CallExpression on a known logger binding, the
    object literal passed to child() is folded into the field set.
  - >
    Pino mixin / Winston format — the logger is constructed as
    `pino({ mixin: () => ({ correlation_id: getCid() }) })` or
    `winston.format.combine(winston.format.timestamp(), customFormat)`,
    which adds fields inside every emitted record regardless of what
    the call site passes. From the call-site perspective the fields
    appear missing; from the runtime output perspective they are
    present. This is out-of-scope for a static rule (the mixin/format
    is a closure the analyser cannot evaluate) and the charter
    acknowledges the gap: when a recognised mixin/format constructor
    is detected in scope, the call's confidence is capped lower and a
    PRESENT mitigation records the ambiguity.
  - >
    Wrapper-function context injection — the handler delegates to a
    `logEvent(event, details)` helper imported from a local module
    that internally calls `logger.info({ correlation_id, ...details },
    event)`. At the call site in the handler the arguments look like
    a bare string and a shallow object, but the wrapper re-shapes
    them. The rule treats recognised wrapper names (`logEvent`,
    `audit`, `emit`, `track`, `record`) as indirect structured
    logging — not firing on those calls, consistent with K1's
    indirect-logger-detection strategy.
  - >
    Template-literal log with interpolation — the handler writes
    `logger.info(\`request ${requestId} user ${userId} outcome ${outcome}\`)`.
    The interpolation mentions the required fields textually but the
    call carries no object literal, so the fields are stringified into
    the message body rather than emitted as structured JSON. A static
    rule that says "has requestId? yes → OK" is wrong because the
    runtime record remains a single unstructured string; the rule
    must distinguish "field present as structured property" from
    "field name appears inside the string". Template literals with no
    object argument are treated as string-only calls.
  - >
    Shadowed logger identifier — a utility module defines
    `const logger = { info: console.log }` shadowing the structured
    logger binding with a console wrapper. The call `logger.info(...)`
    looks like structured logging at the receiver but is actually a
    console passthrough. This is out of scope for K20 — the
    assignment-level misconfiguration is a K1 handler-scope concern
    (the handler's effective logger is console). The charter
    acknowledges the gap.

edge_case_strategies:
  - spread-assignment-opacity        # SpreadAssignment silences emptiness verdict
  - child-bindings-field-resolution  # logger.child({...}).info({...}) — fold bindings
  - mixin-format-presence            # pino({mixin}) / winston format → PRESENT mitigation
  - indirect-structured-wrapper      # logEvent/audit/emit/track/record → do not fire
  - template-literal-no-structure    # template literals with interpolation ≠ structure

evidence_contract:
  minimum_chain:
    source: true        # the logger call site
    propagation: false  # optional — bindings chain propagation when child() observed
    sink: true          # the audit-context gap at the call site
    mitigation: true    # must report which fields ARE and ARE NOT observable
    impact: true        # must describe the concrete audit-correlation failure
  required_factors:
    - audit_fields_observed_count   # how many recognised aliases appeared at the call
    - structured_logger_in_file     # whether the file imports a structured logger
    - call_receiver_shape           # console | known-binding | child-chain | wrapper
  location_kinds:
    - source            # file:line:col for the call site and bindings site
    - dependency        # package.json entry for the structured logger (when present)

obsolescence:
  retire_when: >
    The MCP specification mandates that every tool invocation record is
    emitted by the protocol itself with correlation id / caller identity /
    tool name / timestamp / outcome as protocol-level fields — so a
    handler's internal logging adequacy no longer gates the audit
    record. Alternatively, retire when ISO/IEC 27001:2022 A.8.15 is
    superseded by a control that does not require structured fields.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# K20 — Insufficient Audit Context in Logging

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers whose TypeScript/JavaScript source contains
logger call sites — whether via `console.*`, a known structured logger
binding (`pino`, `winston`, `bunyan`, `tslog`, `log4js`, `loglevel`,
`signale`, `consola`, `roarr`, `structlog`, `loguru`, `logging`), or a
conventional logger identifier (`logger`, `log`).

## What a regulator accepts as evidence

An ISO 27001:2022 A.8.15 auditor asks whether the event logs produced
by a system are analysable. A log record that collapses to a bare
message string — `"handled tool call"` — carries no identifier that
ties it to the request, the caller, or the tool that was invoked. If
the server also emits records from `console.log`, the records are
produced but have no retention guarantee and no machine-parseable
fields; the A.8.15 requirement to "protect and analyse" logs cannot
be met on the record-keeping dimension.

The rule names, per call site:

1. **Call-site proof** — a `source`-kind Location pointing at the
   exact `logger.info(...)` / `console.log(...)` / `log.warn(...)`
   line that the audit trail originates from.

2. **Field gap proof** — a structural enumeration of the property
   names observable on any object-literal argument to the call, plus
   the property names observable on any `.child(<obj>)` bindings on
   the call receiver. The observed set is compared against five
   recognised audit-field groups: correlation / caller identity /
   tool or operation / timestamp / outcome. A call is "insufficient"
   when the observed-alias count is below
   `AUDIT_FIELD_THRESHOLD` (=2).

3. **Mitigation check** — whether a structured logger import is
   present in the same file (so the developer chose to bypass a
   logger that was available), whether the call receiver has a
   `.child(...)` binding that adds opaque fields, and whether a
   pino mixin / winston format constructor is detected in scope.
   Each mitigation is emitted with a structured Location (source
   or dependency).

4. **Impact statement** — a concrete description of the operational
   loss: an incident responder opening the log for this call cannot
   correlate it to a request id, cannot attribute it to a user or
   session, cannot determine the tool invoked, and cannot tell
   whether the operation succeeded — which directly forecloses the
   timeline reconstruction ISO 27001 A.8.15 audit guidance requires.

## What the rule does NOT claim

- It does not claim that every console.* call is insufficient. When a
  structured logger is imported in the file, console.* calls are
  deferred to K1 (handler-scope structured-logger coverage).
- It does not attempt to determine whether the specific correlation id
  propagated is unique per request — that is a runtime property.
- It does not evaluate mixin/format closures or mixed context
  propagation at runtime — acknowledged in the third lethal edge case.
- It does not flag calls that carry a SpreadAssignment on the object
  literal; a spread is treated as opaque context that may carry the
  required fields (acknowledged false-negative window).

## Why confidence is capped at 0.85

The reachable static proof is that the call site's observable property
names do not contain ≥2 audit-field aliases. A runtime-attached
mechanism — pino mixin, winston format transform, AsyncLocalStorage
context — can inject the fields invisibly. The cap at 0.85 preserves
room for that uncertainty rather than overclaiming on a static
observation.

## Interaction with K1

K1 fires when a handler emits its events through `console.*` with no
structured logger in scope — the architectural gap. K20 fires when a
specific call site (including structured-logger call sites) emits a
record that, even after bindings propagation, carries fewer than the
threshold number of audit-field aliases — the per-call completeness
gap. They intentionally cover different angles; a code path with a
console.log inside a registered handler in a file with no logger import
will produce both a K1 and a K20 finding, because it fails on both
dimensions.
