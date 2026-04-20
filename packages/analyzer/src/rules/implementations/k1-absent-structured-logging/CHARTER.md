---
rule_id: K1
interface_version: v2
severity: high

threat_refs:
  - kind: spec
    id: ISO-27001-A.8.15
    url: https://www.iso.org/standard/82875.html
    summary: >
      Event logs recording user activities, exceptions, faults, and information
      security events shall be produced, stored, protected, and analysed. A
      console.log stream in production code is not "produced, stored, protected,
      and analysed" — it is discarded to stdout with no structure, no retention,
      no integrity guarantee.
  - kind: spec
    id: EU-AI-Act-Art-12
    url: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
    summary: >
      High-risk AI systems shall technically allow for the automatic recording
      of events ("logs") over the duration of the system's lifetime. The
      MCP-exposed surface of an AI agent is exactly the "events" the Article 12
      regime needs to see — tool invocations, parameters, caller identity.
      console.log produces neither the structure nor the retention the article
      requires.
  - kind: spec
    id: CoSAI-MCP-T12
    url: https://www.coalitionforsecureai.org/publications/mcp-threat-taxonomy
    summary: >
      Insufficient logging / monitoring — listed as threat category T12 in the
      CoSAI MCP threat taxonomy (Jan 2026). The taxonomy is explicit that log
      streams from MCP servers must carry correlation ids, caller identity,
      and machine-parseable fields to support cross-service incident response.
  - kind: paper
    id: MAESTRO-L5-Observability
    url: https://cloudsecurityalliance.org/research/topics/multi-agent-threat-modeling
    summary: >
      MAESTRO's Layer 5 (Evaluation & Observability) requires that every agent
      action is reconstructible from the logs alone. A handler that only uses
      console.log leaves a blind spot exactly where the agent interacts with
      the outside world.

lethal_edge_cases:
  - >
    Partial migration — the file imports pino at module scope (so "logger is
    imported" is true) but one legacy tool handler still uses console.log.
    A simple "has logger import?" check passes; the handler-specific check
    must look inside the handler scope.
  - >
    Explicit audit suppression — production code contains
    logging.disable(logging.CRITICAL) or logger.silent = true inside a
    conditional branch that ends up being reachable (e.g. gated on a
    truthy env var). This is a different attack class from "no logger at
    all" and the rule must flag it separately with higher severity.
  - >
    Test-file camouflage — attacker ships a file named
    src/handlers/tool-handler.test.ts that is actually wired into the
    production entry point by package.json. A file-path heuristic that
    skips "*.test.ts" would miss this. The rule must confirm test-nature
    structurally (vitest/jest imports, describe/it blocks) not by name.
  - >
    Alias logger — the logger is imported as `const l = require("pino")()`
    and used as `l.info(...)`. A name-based "does the handler call
    logger.info?" check would miss this. The rule must trace the alias
    binding through the AST, not scan for the literal identifier "logger".
  - >
    Side-effect-only logging — the handler calls `audit(req.body)` where
    `audit` is imported from a local module that internally uses pino.
    This is adequate logging, but a file-local scan sees no pino import
    and no logger.info call. Mitigated by tagging any call to an imported
    symbol named `audit|track|emit|logEvent` as "possible indirect logger
    use" and NOT firing if that signal is strong.
  - >
    Structured logger misconfigured to console transport — pino({ transport:
    { target: "pino-pretty" } }) is fine; pino({ browser: { write: console.log } })
    collapses the signal back to console. This is out-of-scope for a
    static rule (requires runtime config resolution) but the charter
    acknowledges the gap so a future Phase 2 chunk can add it.

edge_case_strategies:
  - handler-scope-taint          # must detect console.X inside a handler scope, not the whole file
  - alias-binding-resolution     # resolve "const l = require('pino')()" → l is a logger
  - audit-erasure                # explicit logging.disable / logger.silent suppressions
  - test-nature-structural       # decide test-vs-prod by AST shape, not by filename
  - indirect-logger-detection    # call to imported audit/emit function counts as logging

evidence_contract:
  minimum_chain:
    source: true        # the console.X call (file:line) OR the disable() call
    propagation: false  # optional — present when the handler wraps the console call
    sink: true          # the compliance gap (audit absence) at the handler Location
    mitigation: true    # MUST report whether a structured logger is present
    impact: true        # must describe the concrete audit failure
  required_factors:
    - ast_handler_scope          # the console call is inside a registered handler (not a utility)
    - logger_import_presence     # whether any structured logger import exists in this file
    - logger_dependency_presence # whether any structured logger is in package.json
  location_kinds:
    - source            # file:line:col for the console call + handler definition
    - dependency        # package.json entry for the structured logger (or absent)
    - config            # package.json path when dependency scan is required

obsolescence:
  retire_when: >
    The MCP specification mandates that every tool invocation emits a
    structured, correlation-id-tagged audit record out of the protocol
    itself (so missing application-level logging no longer produces a
    compliance gap) — OR ISO 27001:2022 A.8.15 is superseded by a control
    that does not require structured application-level event logs.
---

# K1 — Absent Structured Logging

**Author:** Senior MCP Threat Researcher persona.
**Applies to:** MCP servers that register request or tool-call handlers in
TypeScript, JavaScript, or Python source.

## What an auditor accepts as evidence

An ISO 27001:2022 A.8.15 auditor will not accept a rule that says
"no structured logger found in this repository". They will accept a rule
that says:

1. **Scope proof** — the finding names a specific registered handler, with
   a `source`-kind Location that points to the `app.get(...)` /
   `server.setRequestHandler(...)` / `@app.route(...)` declaration. A
   handler is something the server dispatches to when the outside world
   arrives — not a utility function.

2. **Gap proof** — the finding names one or more `console.<method>(...)`
   calls inside the lexical scope of that handler, each with a `source`
   Location. If alias binding is involved (`const l = pino()`) the rule
   follows the binding rather than the literal identifier.

3. **Mitigation check** — the finding states, with structured Locations,
   whether the file imports a structured logger, whether the package
   dependency list carries a structured logger, and (importantly) whether
   the handler itself uses one. A partial-migration result (file-level
   import present, handler-level usage absent) is materially different
   from "no structured logger anywhere in the project" and must be
   confidence-adjusted accordingly.

4. **Impact statement** — a concrete description of what signal is lost:
   no correlation id for cross-service tracing, no machine-parseable
   fields for SIEM ingestion, no retention guarantee — tied explicitly
   to the three frameworks above.

## What the rule does NOT claim

- It does not claim that every console call is a compliance violation.
  A console.log in a utility function not reachable from a handler is
  not flagged.
- It does not claim detection of logger-misconfiguration-at-runtime
  (pino(...).transport = console). That is out-of-scope — see the
  fifth lethal edge case above.

## Why confidence is capped at 0.90

The best reachable proof is static. A rule that sees
`app.post("/x", (req, res) => console.log(req.body))` with no structured
logger anywhere in the file deserves high but not maximal confidence:
there remains a scenario where the server is wrapped by a middleware
layer (e.g. morgan piped to syslog) that is not visible at file scope.
The confidence cap at 0.90 preserves room for that uncertainty rather
than overclaiming.
