# Detection Rules — CLAUDE.md

## What This Directory Contains

177 YAML detection rule definitions across 17 categories (A–Q). The analyzer engine (`packages/analyzer`) loads and interprets these at runtime. **Rules are data, not code** (ADR-005) — adding a rule should never require changing engine code.

## Before You Start

Read `agent_docs/detection-rules.md` before adding, editing, or disabling any rule. It contains the full specification, engine handler status, and threat intelligence sources for every category.

## Rule File Structure

Every rule YAML must have these required fields:

```yaml
id: C1                                    # Category letter + number (unique across all rules)
name: Command Injection                   # Human-readable name
category: code-analysis                   # Must match a valid category (see below)
severity: critical                        # critical | high | medium | low | informational
owasp: MCP03-command-injection            # OWASP MCP Top 10 ID (MCP01–MCP10) or null
mitre: AML.T0054                          # MITRE ATLAS technique ID or null
detect:
  type: regex                             # regex | schema-check | behavioral | composite
  patterns:                               # For regex type: array of regex strings
    - "exec\\s*\\("
    - "execSync\\s*\\("
  context: source_code                    # What text the patterns run against (see below)
  exclude_patterns:                       # Optional: suppress match if these also match
    - "// safe: sanitized input"
remediation: "Replace exec() with..."     # Actionable fix — REQUIRED, never leave empty
test_cases:
  true_positive:                          # Minimum 2 required
    - { description: "...", expected: true }
    - { description: "...", expected: true }
  true_negative:                          # Minimum 2 required
    - { description: "...", expected: false }
    - { description: "...", expected: false }
enabled: true                             # Set false to disable without deleting
```

## Valid Categories

| Category Value | Sub-Score | Rule IDs |
|---|---|---|
| `description-analysis` | `description_score` | A1–A9 |
| `schema-analysis` | `config_score` | B1–B7 |
| `code-analysis` | `code_score` | C1–C16 |
| `dependency-analysis` | `deps_score` | D1–D7 |
| `behavioral-analysis` | `behavior_score` | E1–E4 |
| `ecosystem-context` | `config_score` | F1–F7 |
| `adversarial-ai` | `config_score` | G1–G7 |
| `auth-analysis` | `config_score` | H1–H3 |
| `protocol-surface` | `config_score` | I1–I16 |
| `threat-intelligence` | `config_score` | J1–J7 |
| `compliance-governance` | `config_score` | K1–K20 |
| `supply-chain-advanced` | `config_score` | L1–L15 |
| `ai-runtime-exploitation` | `config_score` | M1–M9 |
| `protocol-edge-cases` | `config_score` | N1–N15 |
| `data-privacy-attacks` | `config_score` | O1–O10 |
| `infrastructure-runtime` | `config_score` | P1–P10 |
| `cross-ecosystem-emergent` | `config_score` | Q1–Q15 |

## Valid Context Types (for `detect.context`)

| Context | What Gets Scanned | Used By |
|---|---|---|
| `tool_description` | Each tool's `name + " " + description` | A1–A9, G2, G3, G5, J6 |
| `parameter_description` | Parameter-level `description` fields inside `input_schema` | B5 |
| `parameter_schema` | Stringified `input_schema` + `output_schema` | B2, J3 |
| `source_code` | Concatenated source code string | C1–C16, H1, J1–J5, J7, K1–K20, L–Q |
| `metadata` | Server `name + description` + all tool names | A3, A4 |
| `server_initialize_fields` | `serverInfo.name + version + instructions` from initialize handshake | H2 |
| `resource_metadata` | Resource URIs + names + descriptions | I3 |
| `prompt_metadata` | Prompt names + descriptions + argument names | I6 |
| `tool_annotations` | Serialized annotation objects (readOnlyHint, destructiveHint, etc.) | I1, I2 |

## Valid Severity Values and Scoring Impact

| Value | Score Penalty |
|---|---|
| `critical` | -25 points |
| `high` | -15 points |
| `medium` | -8 points |
| `low` | -3 points |
| `informational` | -1 point |

## Detect Types and Their Handlers

| `detect.type` | Engine Handler | When to Use |
|---|---|---|
| `regex` | `runRegexRule()` | Pattern matching against text contexts. Most common. |
| `schema-check` | `runSchemaCheckRule()` | Structural checks on tool schemas (parameter count, missing constraints, dangerous defaults). |
| `behavioral` | `runBehavioralRule()` | Connection-time checks (auth, transport, response time, tool drift). |
| `composite` | `runCompositeRule()` | Multi-signal analysis requiring cross-tool or cross-field logic (lethal trifecta, data flow, namespace squatting). |

## CRITICAL: Detection Quality Standards — No Toy Regex

**YAML regex patterns are the LAST resort, not the default.** Simple regex in YAML produces high false-positive rates and misses real attacks. Every new rule must use the most technically rigorous detection method available.

### Decision ladder (use the FIRST option that applies)

1. **Typed Rule (TypeScript implementation)** — Preferred for any rule requiring real analysis. Write a class in `packages/analyzer/src/rules/implementations/` that implements the `TypedRule` interface. This gives you access to:
   - **AST-based analysis** — Parse source code into syntax trees (tree-sitter) and walk nodes. Detects actual code structure, not string coincidences. See `c1-command-injection.ts`.
   - **Taint flow analysis** — Track data from sources (user input, external APIs) to sinks (exec, eval, SQL). Cross-function, cross-module propagation. See `taint.ts`, `taint-python.ts`, `taint-ast.ts`.
   - **String distance algorithms** — Levenshtein, Jaro-Winkler, Damerau-Levenshtein for typosquatting, namespace squatting, homoglyph detection. See `similarity.ts`, `d3-typosquatting.ts`.
   - **Entropy analysis** — Shannon entropy with sliding windows for secret detection, encoded payload detection. See `entropy.ts`.
   - **Unicode normalization** — Confusable detection, script mixing analysis, zero-width character categorization. See `unicode.ts`, `a6-unicode-homoglyph.ts`.
   - **Capability graph analysis** — Model tool capabilities as a directed graph, detect dangerous capability combinations. See `capability-graph.ts`, `f1-lethal-trifecta.ts`.
   - **Schema inference** — Structural analysis of JSON schemas, type system reasoning. See `schema-inference.ts`.
   - **Cryptographic fingerprinting** — SHA-256 content hashing with field-level granularity for drift detection. See `tool-fingerprint.ts`.

2. **Composite rule handler** — For multi-signal detection that requires cross-tool, cross-field, or historical analysis. The composite handler in `engine.ts` already supports 28+ check types. If your detection logic needs to reason across multiple tools, combine capability signals, or compare against baselines, add a new composite check type.

3. **Schema-check handler** — For structural validation of tool schemas (parameter counts, constraint presence, dangerous defaults, additional properties). Pure schema reasoning, no string matching.

4. **Behavioral handler** — For connection-time and temporal analysis (auth detection, transport security, response timing, capability drift over scan history).

5. **YAML regex (last resort)** — Only acceptable when ALL of the following are true:
   - The pattern is genuinely a string-literal match (e.g., a specific function name, a known malicious package name, a protocol token)
   - No structural/semantic understanding is needed
   - False positive rate is demonstrably low (<5%) based on test fixtures
   - The pattern cannot be improved by any of the above methods

### What "production-grade detection" looks like

| BAD (toy regex) | GOOD (real analysis) |
|---|---|
| `"eval\\("` matches comments, strings, safe wrappers | AST-based: only flags `eval()` where argument traces to user input via taint flow |
| `"password"` matches variable declarations, docs, constants | Entropy analysis: detects high-entropy strings near assignment operators in credential contexts |
| `"exec\\s*\\("` matches `execFile()` (safe) | AST walker: distinguishes `exec(userInput)` from `execFile(binary, [sanitized])` by argument origin |
| `"mcp-server"` for typosquatting | Levenshtein + Jaro-Winkler similarity against 60+ known package names with configurable threshold |
| `"\\<\\|system\\|\\>"` for prompt injection | Multi-signal: token detection + context position analysis + entropy of surrounding text + role injection pattern clustering |

### When writing YAML regex patterns (if you must)

- Patterns must be **precise and narrow** — anchor to structural context, not just keywords
- Use **negative lookahead/lookbehind** (`(?!...)`, `(?<!...)`) to reduce false positives
- Use **non-greedy quantifiers** (`*?`, `+?`) to avoid catastrophic backtracking (we detect ReDoS — rule C11 — don't introduce it)
- Use **character classes** over alternation where possible (`[aA]` not `(a|A)`)
- Combine multiple signals in `patterns` array — a single vague pattern is never acceptable
- Always provide `exclude_patterns` to suppress known-safe contexts (test files, documentation, security tooling)
- Test against the red-team fixture suite — if precision drops below 80%, the pattern is too broad

## Naming Convention

Files are named `{ID}-{kebab-case-name}.yaml`:
- `A1-prompt-injection.yaml`
- `C10-prototype-pollution.yaml`
- `K20-insufficient-audit-context.yaml`

## Adding a New Rule — Checklist

1. Pick the next ID in the appropriate category (e.g., if last is K20, next is K21)
2. Create `rules/{ID}-{kebab-case-name}.yaml` with ALL required fields
3. Write minimum 2 true positive + 2 true negative test cases
4. If `detect.type` is `composite` or `behavioral`, verify the handler exists in `packages/analyzer/src/engine.ts` — these require engine support
5. If using a new `context` value, it must be added to `getTextsForContext()` in the engine
6. Run `tools/scripts/validate-rules.sh` to validate structure
7. Run `pnpm test --filter=analyzer` to verify rule loads and fires correctly
8. Add red-team fixtures in `packages/red-team/src/fixtures/` for the new rule's category
9. Run `pnpm red-team --rule {ID}` to verify precision/recall
10. Update `agent_docs/detection-rules.md` with the new rule entry

Use the `/add-detection-rule` skill for a guided walkthrough.

## What NOT to Do

- Do NOT create rules with `detect.type: composite` or `detect.type: behavioral` unless the composite/behavioral check already exists in the engine. These require corresponding TypeScript handlers.
- Do NOT omit `remediation` — findings without remediation are useless to users.
- Do NOT omit `test_cases` — the post-edit hook and CI will reject rules without them.
- Do NOT use severity `critical` unless the finding represents a directly exploitable vulnerability. Overuse of critical dilutes scoring.
- Do NOT change `id` of an existing rule — IDs are referenced in findings, scores, OWASP mappings, fixture files, and documentation.
- Do NOT delete a rule file to disable it — set `enabled: false` instead. Historical findings reference the rule ID.
- Do NOT put regex patterns with unescaped special YAML characters. Use double-quoted strings for patterns containing `: [ ] { } , # & * ? | - < > = ! % @`.

## Validation

- **Post-edit hook**: `.claude/hooks/post-edit/validate-rule-yaml.sh` runs automatically after every edit to a YAML file in this directory. It checks required fields, severity values, and test case counts.
- **Script**: `tools/scripts/validate-rules.sh` validates all 177 rules in batch.
- **CI**: `accuracy.yml` workflow runs the full red-team fixture suite and enforces >=80% precision.
