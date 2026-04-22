---
rule_id: C4
interface_version: v2
severity: critical

threat_refs:
  - kind: spec
    id: OWASP-MCP03-sql-injection
    url: https://genai.owasp.org/llm-top-10/
    summary: >
      OWASP MCP Top 10 category MCP03 — Command / Query Injection. Covers
      unsanitised user input embedded in a SQL query string or passed as the
      first argument to a raw-query API. Cited as the controlling reference
      so every finding carries the MCP03 category tag.
  - kind: spec
    id: CWE-89-sql-injection
    url: https://cwe.mitre.org/data/definitions/89.html
    summary: >
      CWE-89 SQL Injection. The canonical weakness class: user input is
      concatenated into a query string or passed as a template literal
      substitution without going through a prepared statement. Used by
      the charter as the structural description of the sink category.
  - kind: paper
    id: MITRE-ATLAS-T0054-LLM-prompt-injection
    url: https://atlas.mitre.org/techniques/AML.T0054
    summary: >
      MITRE ATLAS AML.T0054 — LLM Prompt Injection. When an agent is the
      intermediary filling tool parameters from user prompts, a SQL-injection
      payload crafted in natural language becomes the attack surface the
      agent propagates. Establishes why the source_type for C4 findings is
      "user-parameter" rather than "external-content".

lethal_edge_cases:
  - >
    Tagged-template-literal sanitiser — `db.sql\`SELECT * FROM t WHERE id =
    ${id}\`` where `db.sql` is a tagged template that parameterises every
    substitution. A rule that only checks for template-literal substitutions
    inside .query / .execute / .raw would fire on this safe pattern. The
    charter resolves this by letting the AST taint analyser's sink taxonomy
    (which does not include tagged-template tags) make the call: the tag
    function itself is the sanitiser. Findings produced here are false
    positives and must be suppressed by the sanitiser-present path.
  - >
    Numeric coercion used as a weak sanitiser — `const id = Number(req.body.id);
    db.query(\`SELECT * FROM t WHERE id = ${id}\`)`. The programmer believes
    `Number()` is a sanitiser because the coerced value cannot contain quotes.
    The charter treats `Number`, `parseInt`, `parseFloat` as sanitisers only
    for `sql_query` + `sql_injection` categories (the AST taint engine already
    encodes this in its SANITIZERS map) — but the finding still fires at
    `informational` severity because the coercion is fragile: if the column
    is a string, `Number("1 OR 1=1")` returns NaN which an app may stringify
    back into the query.
  - >
    Dynamic table / column name — `db.query(\`SELECT * FROM \${tableName}\`)`.
    A parameterised query using `?` placeholders cannot replace an identifier,
    only a value. Users who understand "prepared statements are safe" may
    still build identifier names from user input. The AST analyser flags
    this because there is still a template-literal substitution in the
    .query() call; the sink_type on the chain is correctly `sql-execution`
    because the exploit surface is the identifier, not a value placeholder.
  - >
    Second-order SQL injection — `const stored = await db.one('SELECT * FROM
    users WHERE id = $1', [id]); db.query(\`SELECT * FROM logs WHERE user =
    '\${stored.name}'\`)`. The first query is safe (parameterised) but its
    result is used unsanitised in a second query whose template literal
    embeds `stored.name`. AST taint analysis does NOT follow data through
    a first-query round-trip (this would require modelling the database as
    a source); the charter acknowledges this as an out-of-scope case —
    handled by the `database-content` source category on C4 findings when
    the lightweight analyser observes it, and by a manual-review note in
    the verification step when AST taint alone is used.
  - >
    ORM literal passthrough — `prisma.$queryRaw\`SELECT * FROM t WHERE id =
    ${id}\``. Prisma's `$queryRaw` IS a tagged template that parameterises,
    but `prisma.$queryRawUnsafe` is NOT — the two are one letter apart. The
    charter requires the finding to reference the sink expression verbatim
    (via `sink.observed`) so an auditor comparing `$queryRaw` vs
    `$queryRawUnsafe` can decide the outcome from the evidence chain
    without re-reading the scanner source.

edge_case_strategies:
  - sanitizer-verified-by-name            # parameterise/prepare/Number/validate drop severity to informational
  - dynamic-identifier-interpolation      # identifier-position substitutions stay critical
  - tagged-template-parameterisation      # AST analyser distinguishes .sql`…` from .query(`…`)
  - second-order-sql-injection            # database-content source category + manual-review verification step
  - ast-taint-interprocedural             # tracks source→sink across assignments, destructures, returns
  - lightweight-taint-fallback            # covers Python f-string / %-format cases AST analyser misses

evidence_contract:
  minimum_chain:
    source: true
    propagation: false                    # optional — direct-on-same-line flows have zero hops
    sink: true
    mitigation: true                      # always records sanitiser present/absent status
    impact: true
  required_factors:
    - ast_confirmed                       # positive — AST analyser confirmed the flow
    - lightweight_taint_fallback          # emitted when only the lightweight analyser saw it
    - interprocedural_hops                # hop count tuning factor
    - unverified_sanitizer_identity       # emitted when sanitiser is on the path but NOT on charter allowlist
    - charter_confidence_cap              # emitted when the 0.92 cap is hit
  location_kinds:
    - source                              # file:line:col for source, every propagation hop, and sink

obsolescence:
  retire_when: >
    Every mainstream Node.js / Python database client rejects raw-query APIs
    at the type level when the argument contains untyped variables — i.e.
    the compiler itself prevents `db.query(templateLiteralWithVariables)`.
    Until the ecosystem adopts TemplateStringsArray-only raw-query surfaces
    (Prisma's $queryRaw is the prototype; pg and mysql2 have not yet
    followed), C4 remains at critical severity.

mutations_survived:
  - split-string-literal
  - unicode-homoglyph-identifier
  - base64-wrap-payload
mutations_acknowledged_blind: []
---

# C4 — SQL Injection (Taint-Aware)

**Author:** Senior MCP Threat Researcher persona (adversarial).
**Applies to:** MCP servers in TypeScript, JavaScript, or Python whose
source code is available and which call a raw-query database API.

## What an auditor accepts as evidence

A MCP03 / CWE-89 auditor will not accept "this server calls .query()". They
accept a structured chain showing:

1. **Source** — a `source`-kind Location on the AST node where untrusted
   data enters (`req.body.*`, `event.arguments.*`, MCP tool argument,
   `process.env.*`, `request.form[…]`).

2. **Propagation** — one propagation link per AST hop (assignment,
   destructure, template-embed, parameter-bind, return). Single-hop flows
   have zero propagation links and a "trivial" exploitability scenario.

3. **Sink** — a `source`-kind Location on the `.query` / `.execute` /
   `.raw` / `cursor.execute` call. `sink.sink_type = "sql-execution"`,
   `cve_precedent = "CWE-89"`. The expression text on `sink.observed`
   preserves the .query-vs-$queryRaw distinction an auditor needs.

4. **Mitigation** — always present, with `present: true` when a
   parameteriser / validator lies on the path (charter-known names:
   prepare, parameterise, Number, parseInt, validate, zod.parse, …) and
   `present: false` otherwise.

5. **Impact** — `data-exfiltration`, scope `connected-services`
   (the database holds the rows; the MCP server host is not directly
   compromised unless the DBMS supports in-engine command execution).
   Exploitability = `trivial` on direct flows, `moderate` on multi-hop.

6. **Verification steps** — one per distinct AST hop, each with a
   source-kind Location. An auditor disputing the finding walks the
   chain without re-running the scanner.

## Why confidence is capped at 0.92

AST-confirmed in-file taint is the strongest static proof, but the 0.08
gap exists for:

- ORM query-builder wrappers that look like raw-query calls but are in
  fact parameterised (Knex, Drizzle, Kysely) — the AST analyser does not
  model every wrapper's semantics;
- tagged-template-based parameterisers whose tag function lies outside
  the SANITIZERS map;
- second-order flows where a prior parameterised query "cleans" the
  data in the reader's intuition but does not actually sanitise.

The 0.92 cap is visible as a `charter_confidence_cap` factor on every
AST-confirmed chain whose raw confidence exceeds it.
