# Detection Rules — CLAUDE.md

## What This Directory Contains

177 detection rule definitions across 17 categories (A–Q). The YAML files define rule **metadata** (id, name, severity, OWASP/MITRE mappings, test cases). The actual detection logic lives in **TypeScript** inside `packages/analyzer/`. YAML is the rule registry; TypeScript is the detection engine.

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
  type: typed                             # Detection logic lives in TypeScript (see below)
  engine: code-analyzer                   # Which specialized engine handles this rule
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

**Note:** Legacy rules may still have `detect.type: regex` with `patterns` arrays. These are technical debt. All new rules MUST use TypeScript implementations. Existing regex rules should be migrated to TypeScript when touched.

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

## Risk Domains (Framework-Driven Categories)

The 13 risk domains are derived from cross-referencing 6 compliance frameworks (OWASP MCP, OWASP ASI, CoSAI, EU AI Act, MITRE ATLAS, MAESTRO). Each rule belongs to exactly one primary risk domain. See `rules/framework-registry.yaml` for the complete mapping.

| Risk Domain | Description | Rule Count | Migration Priority |
|---|---|---|---|
| `prompt-injection` | Prompt injection via descriptions, schemas, init fields, resources | 21 | 8 |
| `tool-poisoning` | Deceptive names, annotations, namespace squatting, drift | 15 | 10 |
| `code-vulnerabilities` | Injection, traversal, SSRF, deserialization, eval | 19 | 9 |
| `data-exfiltration` | Exfiltration via HTTP, DNS, headers, timing, env vars | 20 | 6 |
| `authentication` | OAuth, token lifecycle, credential scope, session mgmt | 9 | 5 |
| `supply-chain-security` | Dependencies, CI/CD, registries, base images, config injection | 26 | 4 |
| `human-oversight` | Confirmation bypass, consent fatigue, kill switches | 7 | 1 |
| `audit-logging` | Logging, audit trails, monitoring context | 5 | 2 |
| `multi-agent-security` | Cross-agent propagation, shared memory, config poisoning | 8 | 7 |
| `protocol-transport` | JSON-RPC, transport, session, batch abuse, smuggling | 18 | 5 |
| `denial-of-service` | Recursion, timeouts, resource exhaustion, cost amplification | 7 | 10 |
| `container-runtime` | Containers, sockets, filesystem, network, crypto | 10 | 3 |
| `model-manipulation` | Special tokens, reasoning chains, schema weaknesses | 12 | 10 |

Migration priority 1 = migrate first (EU AI Act deadline-driven), 10 = migrate last.

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

## Detect Types

| `detect.type` | Where Logic Lives | When to Use |
|---|---|---|
| `typed` | `packages/analyzer/src/rules/implementations/` | **ALL new rules.** TypeScript class implementing `TypedRule` interface. |
| `composite` | `runCompositeRule()` in `engine.ts` | Multi-signal detection requiring cross-tool, cross-field, or historical analysis. 28+ check types already exist. |
| `schema-check` | `runSchemaCheckRule()` in `engine.ts` | Structural validation of tool schemas (parameter counts, constraints, dangerous defaults). |
| `behavioral` | `runBehavioralRule()` in `engine.ts` | Connection-time and temporal analysis (auth, transport, response timing, capability drift). |
| `regex` | **BANNED for new rules.** Legacy only. | Existing regex rules are technical debt to be migrated. |

## ABSOLUTE RULE: No YAML Regex — TypeScript Only

**Do NOT write detection logic as YAML regex patterns. Period.**

YAML regex is fundamentally inadequate for security detection:
- It matches strings, not code structure — fires on comments, string literals, documentation, safe wrappers
- It cannot track data flow — cannot distinguish `exec(userInput)` from `exec("ls")`
- It cannot reason about context — cannot tell if a pattern appears in a test file vs production code
- It produces unacceptable false positive rates that destroy user trust
- It is unmaintainable — complex regex in YAML is unreadable, untestable, and fragile

**Every new rule MUST have a TypeScript implementation.** The YAML file defines metadata only (id, name, severity, OWASP/MITRE, test cases). The detection algorithm lives in TypeScript where it has access to real analysis techniques.

### How to implement detection for a new rule

Write a TypeScript class in `packages/analyzer/src/rules/implementations/{id}-{name}.ts` implementing the `TypedRule` interface. You have access to the full analysis toolkit:

**Code Analysis Techniques:**
- **AST parsing** (tree-sitter) — Walk syntax trees, inspect node types, understand code structure. See `c1-command-injection.ts`.
- **Taint flow analysis** — Track data propagation from sources (user input, external APIs) to dangerous sinks (exec, eval, SQL). Cross-function, cross-module. See `taint.ts`, `taint-python.ts`, `taint-ast.ts`.
- **Control flow analysis** — Understand branching, loop bounds, reachability. Built on top of AST.

**String & Data Analysis Techniques:**
- **String distance algorithms** — Levenshtein, Jaro-Winkler, Damerau-Levenshtein for typosquatting, namespace squatting, homoglyph detection. See `similarity.ts`, `d3-typosquatting.ts`.
- **Shannon entropy** — Sliding-window entropy analysis for secret detection, encoded payload detection, randomness measurement. See `entropy.ts`.
- **Unicode normalization** — Confusable detection, script mixing analysis, zero-width character categorization, homoglyph mapping. See `unicode.ts`, `a6-unicode-homoglyph.ts`.

**Structural Analysis Techniques:**
- **Capability graph analysis** — Model tool capabilities as a directed graph, detect dangerous capability combinations, identify attack chains. See `capability-graph.ts`, `f1-lethal-trifecta.ts`.
- **Schema inference** — Structural analysis of JSON schemas, type system reasoning, constraint validation. See `schema-inference.ts`.
- **Module dependency graph** — Cross-file import resolution, dependency chain analysis. See `module-graph.ts`.
- **Cryptographic fingerprinting** — SHA-256 content hashing with field-level granularity for drift/rug-pull detection. See `tool-fingerprint.ts`.

### What production-grade detection looks like

| Problem | Correct Approach |
|---|---|
| Detect `eval()` with user input | AST-based taint flow: parse source, identify `eval()` call nodes, trace arguments back to user input sources |
| Detect hardcoded secrets | Entropy analysis: sliding window over string literals, flag high-entropy values near assignment operators in credential-like contexts |
| Detect `exec()` vs safe `execFile()` | AST walker: distinguish by function name node + argument origin analysis (tainted vs constant) |
| Detect typosquatting packages | Levenshtein + Jaro-Winkler similarity against 60+ known package names with configurable threshold |
| Detect prompt injection in descriptions | Multi-signal: LLM special token detection + context position analysis + entropy of surrounding text + role injection pattern clustering |
| Detect capability drift over time | Cryptographic fingerprinting: SHA-256 tool pins with field-level diff, threshold-based alerting |
| Detect dangerous capability combinations | Capability graph: model read/write/execute/network as directed edges, detect lethal patterns via graph traversal |

### Migrating existing regex rules

When touching an existing rule that uses `detect.type: regex`, migrate it:
1. Create a TypeScript implementation in `packages/analyzer/src/rules/implementations/`
2. Register it in `packages/analyzer/src/rules/index.ts`
3. Update the YAML `detect.type` to `typed`
4. Remove the `patterns` and `context` fields from the YAML
5. Verify with red-team fixtures that precision improves or stays the same

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

- **Do NOT write YAML regex patterns for new rules.** This is the single most important rule in this file. All detection logic must be implemented in TypeScript. No exceptions.
- Do NOT create rules with `detect.type: composite` or `detect.type: behavioral` unless the composite/behavioral check already exists in the engine. These require corresponding TypeScript handlers.
- Do NOT omit `remediation` — findings without remediation are useless to users.
- Do NOT omit `test_cases` — the post-edit hook and CI will reject rules without them.
- Do NOT use severity `critical` unless the finding represents a directly exploitable vulnerability. Overuse of critical dilutes scoring.
- Do NOT change `id` of an existing rule — IDs are referenced in findings, scores, OWASP mappings, fixture files, and documentation.
- Do NOT delete a rule file to disable it — set `enabled: false` instead. Historical findings reference the rule ID.

## Validation

- **Post-edit hook**: `.claude/hooks/post-edit/validate-rule-yaml.sh` runs automatically after every edit to a YAML file in this directory. It checks required fields, severity values, and test case counts.
- **Script**: `tools/scripts/validate-rules.sh` validates all 177 rules in batch.
- **CI**: `accuracy.yml` workflow runs the full red-team fixture suite and enforces >=80% precision.
