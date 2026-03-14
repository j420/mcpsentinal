# Skill: Add Detection Rule

Use this skill whenever adding a new detection rule to MCP Sentinel.
Adding a rule incorrectly causes silent failures — rules that ship but never fire.
D3 and F4 shipped as stubs because this process wasn't followed.

## When to Use
- User asks you to add a new detection rule
- A new CVE or attack pattern requires a new rule
- Extending an existing rule category (e.g., adding Azure patterns to C3)

## Pre-Flight Checklist
Before writing any YAML, answer these:
1. Does an existing rule already cover this? Check `rules/` and `agent_docs/detection-rules.md`
2. What rule ID should this be? Next available in its category (e.g., next after H3 is I1)
3. What `detect.type` fits? `regex` / `schema-check` / `behavioral` / `composite`
4. Does the engine already handle this `detect.type` + `context` combination? Check the handler table in `agent_docs/detection-rules.md`

## Step-by-Step

### Step 1: Create the YAML file
File path: `rules/<ID>-<short-name>.yaml`

Required structure (every field is mandatory):
```yaml
id: <ID>                          # e.g., I1
name: <Human readable name>
category: <category>              # code-analysis | dependency-analysis | behavioral-analysis | description-analysis | schema-analysis | ecosystem-context | adversarial-ai | 2026-attack-surface
severity: <severity>              # critical | high | medium | low | informational
owasp: <MCP01–MCP10>
mitre: <AML.T****>
detect:
  type: <regex|schema-check|behavioral|composite>
  # For regex:
  patterns:
    - "pattern1"
    - "pattern2"
  context: <tool_description|parameter_description|source_code|metadata|parameter_schema|server_initialize_fields>
  exclude_patterns:               # optional
    - "// safe: ..."
  # For schema-check:
  check: <check_type>
  threshold: <number>             # if applicable
  # For composite:
  check: <composite_check_type>
remediation: "One sentence: what the developer should do to fix this."
test_cases:
  true_positive:
    - { file: "fixtures/<vuln-example>.ts", expected: true }
    - { file: "fixtures/<vuln-example-2>.ts", expected: true }
  true_negative:
    - { file: "fixtures/<safe-example>.ts", expected: false }
    - { file: "fixtures/<safe-example-2>.ts", expected: false }
```

### Step 2: Verify the engine handles this rule type
Open `agent_docs/detection-rules.md` → Engine Implementation Status table.
Confirm there is a `✅` for your `detect.type` + `context` combination.

If the combination is NOT in the table:
- You must add a handler to `packages/analyzer/src/engine.ts`
- Add the new handler to `getTextsForContext()` or add a new `runXRule()` method
- Update the Engine Implementation Status table in `agent_docs/detection-rules.md`

### Step 3: Update detection-rules.md
In `agent_docs/detection-rules.md`:
1. Add the rule to the correct category table (with ID, Name, Severity, description)
2. Update the rule count in the category header
3. Update the total rule count in the summary table
4. If adding a new engine handler: add it to the Engine Implementation Status table
5. Update the OWASP coverage table if this rule covers a new OWASP category

### Step 4: Write test fixtures (if rule has file-based test cases)
Create fixture files in `data/fixtures/` matching the paths in your `test_cases`.
- True positive fixture: contains the vulnerable pattern
- True negative fixture: the safe equivalent
- Keep fixtures minimal — only the code pattern needed to trigger/not trigger the rule

### Step 5: Run analyzer tests
```bash
pnpm test --filter=analyzer
```
Tests must pass. If they fail:
- Check the regex pattern escaping (YAML requires double-escaping backslashes)
- Check that the `context` field matches where your test fixtures are loaded from
- Check that `exclude_patterns` aren't accidentally matching your true positives

### Step 6: Update product-milestones.md (if new category)
If you added the first rule in a new category (e.g., category I), update Layer 2 deliverables.

## Common Mistakes to Avoid
- **Missing test_cases**: The hook will catch this, but don't rely on it
- **Wrong context**: `source_code` requires GitHub source fetch (Stage 1). Rules using `source_code` context only fire when source code is available
- **Regex not double-escaped in YAML**: `exec\s*\(` in YAML must be `exec\\s*\\(`
- **No remediation**: Must be actionable — tell the developer exactly what to change
- **Rule added to YAML but engine has no handler**: Rule will load but silently produce zero findings

## Validation
The `.claude/hooks/post-edit/validate-rule-yaml.sh` hook will check your YAML automatically.
If it fails, fix the reported errors before continuing.
