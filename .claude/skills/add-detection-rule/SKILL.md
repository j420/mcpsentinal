# Skill: Add Detection Rule

Use this skill whenever adding a new detection rule to MCP Sentinel.
Adding a rule incorrectly causes silent failures — rules that ship but never fire.
D3 and F4 shipped as stubs because this process wasn't followed.

## When to Use
- User asks you to add a new detection rule
- A new CVE or attack pattern requires a new rule
- Extending an existing rule category (e.g., adding Azure patterns to C3)

## CRITICAL: No YAML Regex

**All new rules MUST have TypeScript implementations.** YAML regex patterns are banned.
YAML files define metadata only (id, name, severity, OWASP/MITRE, test cases).
Detection logic lives in TypeScript where it has access to AST parsing, taint tracking,
string distance algorithms, entropy calculation, and other real analysis techniques.

See `rules/CLAUDE.md` for the full rationale.

## Pre-Flight Checklist
Before writing any code, answer these:
1. Does an existing rule already cover this? Check `rules/` and `agent_docs/detection-rules.md`
2. What rule ID should this be? Next available in its category (e.g., next after H3 is I1)
3. What analysis technique fits? AST taint tracking, schema validation, composite logic, behavioral signal?
4. Does an existing specialized engine already handle this domain? Check `packages/analyzer/src/engines/`

## Step-by-Step

### Step 1: Create the YAML metadata file
File path: `rules/<ID>-<short-name>.yaml`

Required structure (every field is mandatory):
```yaml
id: <ID>                          # e.g., I1
name: <Human readable name>
category: <category>              # code-analysis | dependency-analysis | behavioral-analysis | description-analysis | schema-analysis | ecosystem-context | adversarial-ai | auth-analysis | protocol-surface | threat-intelligence | compliance-governance | supply-chain-advanced | ai-runtime-exploitation | protocol-edge-cases | data-privacy-attacks | infrastructure-runtime | cross-ecosystem-emergent
severity: <severity>              # critical | high | medium | low | informational
owasp: <MCP01–MCP10>             # or null
mitre: <AML.T****>               # or null
detect:
  type: typed                     # ALWAYS 'typed' for new rules — YAML regex is BANNED
remediation: "One sentence: what the developer should do to fix this."
enabled: true
test_cases:
  true_positive:
    - { file: "fixtures/<vuln-example>.ts", expected: true }
    - { file: "fixtures/<vuln-example-2>.ts", expected: true }
  true_negative:
    - { file: "fixtures/<safe-example>.ts", expected: false }
    - { file: "fixtures/<safe-example-2>.ts", expected: false }
```

### Step 2: Create the TypeScript implementation
File path: `packages/analyzer/src/rules/implementations/<id>-<short-name>.ts`

Follow the pattern of existing implementations (e.g., `c1-command-injection.ts`, `a6-unicode-homoglyph.ts`):
1. Import `registerTypedRule` from `../base`
2. Implement the detection logic using real analysis techniques
3. Return findings with `rule_id`, `severity`, `evidence`, and `remediation`
4. Call `registerTypedRule()` at module scope to self-register

Available analysis toolkits in `packages/analyzer/src/rules/analyzers/`:
- `taint.ts` — regex-based source→sink flow tracking
- `taint-ast.ts` — TypeScript AST taint analysis
- `taint-python.ts` — Python AST taint analysis
- `entropy.ts` — Shannon entropy for secret detection
- `unicode.ts` — confusables normalization for homoglyph detection
- `similarity.ts` — Jaro-Winkler, Damerau-Levenshtein for typosquatting
- `capability-graph.ts` — tool capability classification
- `schema-inference.ts` — JSON schema structural analysis
- `module-graph.ts` — import/require dependency graphs

### Step 3: Register the implementation
Add an import to `packages/analyzer/src/rules/index.ts` so it auto-registers on engine startup.

### Step 4: Update detection-rules.md
In `agent_docs/detection-rules.md`:
1. Add the rule to the correct category table (with ID, Name, Severity, description)
2. Update the rule count in the category header
3. Update the total rule count in the summary table
4. Add to the Engine Implementation Status table
5. Update the OWASP coverage table if this rule covers a new OWASP category

### Step 5: Write test fixtures (if rule has file-based test cases)
Create fixture files in `data/fixtures/` matching the paths in your `test_cases`.
- True positive fixture: contains the vulnerable pattern
- True negative fixture: the safe equivalent
- Keep fixtures minimal — only the code pattern needed to trigger/not trigger the rule

### Step 6: Run analyzer tests
```bash
pnpm test --filter=analyzer
```
Tests must pass. If they fail:
- Check that the TypeScript implementation is correctly registered
- Check that the `AnalysisContext` contains the data your rule needs
- Check that evidence strings are non-empty

### Step 7: Update product-milestones.md (if new category)
If you added the first rule in a new category, update Layer 2 deliverables.

## Common Mistakes to Avoid
- **Writing YAML regex patterns**: This is the #1 mistake. All detection logic MUST be TypeScript. No exceptions.
- **Missing test_cases**: The hook will catch this, but don't rely on it
- **Wrong context**: `source_code` requires GitHub source fetch (Stage 1). Rules using source code only fire when source code is available
- **No remediation**: Must be actionable — tell the developer exactly what to change
- **Forgetting to register**: Import the implementation in `packages/analyzer/src/rules/index.ts`

## Validation
The `.claude/hooks/post-edit/validate-rule-yaml.sh` hook will check your YAML automatically.
If it fails, fix the reported errors before continuing.
