# Runbook: Add a New Detection Rule

Use this runbook when adding a detection rule triggered by a new CVE, attack pattern, or research finding.
For the AI-assisted workflow, use `.claude/skills/add-detection-rule/SKILL.md` instead.

## Decision: Do You Need a New Rule?

Before creating a new rule, check:
1. `rules/` directory — does an existing rule already cover this pattern?
2. `agent_docs/detection-rules.md` — is this pattern in any existing rule's description?
3. Could you extend an existing rule (e.g., add a pattern to C3) instead of creating a new one?

**Extend an existing rule** when: the new pattern is the same attack class, same OWASP category, same remediation.
**Create a new rule** when: distinct attack class, different OWASP mapping, or different remediation guidance.

## Step 1: Assign Rule ID

Current rule counts by category:
- A: 9 (A1–A9) — next: A10
- B: 7 (B1–B7) — next: B8
- C: 16 (C1–C16) — next: C17
- D: 7 (D1–D7) — next: D8
- E: 4 (E1–E4) — next: E5
- F: 7 (F1–F7) — next: F8
- G: 7 (G1–G7) — next: G8
- H: 3 (H1–H3) — next: H4
- I: 0 — next: I1 (first rule in new category)

## Step 2: Create the YAML File

```bash
touch rules/<ID>-<kebab-name>.yaml
```

Minimum required structure — all fields mandatory:
```yaml
id: <ID>
name: <Human readable name>
category: <code-analysis|dependency-analysis|behavioral-analysis|description-analysis|schema-analysis|ecosystem-context|adversarial-ai|2026-attack-surface>
severity: <critical|high|medium|low|informational>
owasp: <MCP01–MCP10>
mitre: <AML.T****>
detect:
  type: <regex|schema-check|behavioral|composite>
  patterns:        # for regex type
    - "pattern"
  context: <tool_description|parameter_description|source_code|metadata|parameter_schema|server_initialize_fields>
remediation: "Actionable fix for the developer."
test_cases:
  true_positive:
    - { file: "fixtures/vuln-example.ts", expected: true }
    - { file: "fixtures/vuln-example-2.ts", expected: true }
  true_negative:
    - { file: "fixtures/safe-example.ts", expected: false }
    - { file: "fixtures/safe-example-2.ts", expected: false }
```

The `validate-rule-yaml.sh` hook will check the file automatically on save.

## Step 3: Verify Engine Handler

Open `agent_docs/detection-rules.md` → Engine Implementation Status table.
Find your `detect.type` + `context` combination. It must have `✅`.

If it does NOT exist:
1. Open `packages/analyzer/src/engine.ts`
2. Add handling to `getTextsForContext()` (for new context) or add a new `runXRule()` method
3. Add a case to the `runRule()` switch
4. Add `✅ New` to the Engine Implementation Status table

## Step 4: Create Test Fixtures

```bash
mkdir -p data/fixtures
# Create vulnerable file (true positive)
touch data/fixtures/<vuln-example>.ts
# Create safe file (true negative)
touch data/fixtures/<safe-example>.ts
```

Fixtures should be minimal — only the code needed to trigger or not trigger the rule.

## Step 5: Update detection-rules.md

In `agent_docs/detection-rules.md`:
- Add row to the correct category table
- Increment rule count in category header
- Update total count in the summary table
- If new OWASP coverage: update the OWASP coverage table

## Step 6: Run Tests

```bash
pnpm test --filter=analyzer
```

Fix failures before proceeding. Common causes:
- Regex needs double-escaped backslashes in YAML (`\\s` not `\s`)
- Context field doesn't match where test data is loaded
- Exclude patterns accidentally matching true positives

## Step 7: Commit

```bash
git add rules/<ID>-<name>.yaml data/fixtures/ agent_docs/detection-rules.md
git commit -m "rule: add <ID> <name>"
```

## Validation Script

```bash
bash tools/scripts/validate-rules.sh
```

Run this to verify all rules have required fields before any release.
