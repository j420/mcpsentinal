# Skill: Release

Use this skill when preparing a release of MCP Sentinel packages (npm publish, version bump, deploy).

## Pre-Release Checklist (run in order — do not skip steps)

### Step 1: Verify no known issues are open
Check root `CLAUDE.md` → `## Known Issues` section.
Do not release with P0 bugs open unless explicitly approved.

### Step 2: Run the full quality suite
```bash
# All three must pass cleanly — no errors, no warnings
pnpm typecheck
pnpm lint
pnpm test
```
If any fail: stop, fix, restart from Step 1.

### Step 3: Validate all detection rules
```bash
bash tools/scripts/validate-rules.sh
```
All 60+ rules must pass validation (id, severity, detect, remediation, test_cases present).

### Step 4: Build all packages
```bash
pnpm build
```
Verify dist/ directories are populated for: analyzer, scorer, database, api, connector, crawler, cli.

### Step 5: Check for hardcoded secrets
```bash
git diff HEAD --name-only | xargs grep -l "sk-\|ghp_\|AKIA\|xoxb-\|eyJ" 2>/dev/null || echo "clean"
```
If any matches: remove secrets, rotate the exposed credential immediately.

### Step 6: Verify the CLI works end-to-end
```bash
pnpm cli check --json
```
Must output valid JSON with `servers` array. If it errors: do not release.

### Step 7: Version bump
```bash
# Patch: bug fixes only
# Minor: new rules, new crawlers, non-breaking API additions
# Major: breaking API changes, schema migrations

# Update version in root package.json and relevant package package.json files
# Follow semver strictly
```

### Step 8: Update CHANGELOG
Document:
- New rules added (with IDs and CVE references if applicable)
- New crawlers added
- Bug fixes (reference the Known Issues that were resolved)
- Breaking changes (if any)

### Step 9: Git tag and commit
```bash
git add -A
git commit -m "chore: release v<version>"
git tag v<version>
```

### Step 10: Publish CLI to npm (if packages/cli changed)
```bash
cd packages/cli
npm publish --access public
```
Verify: `npx mcp-sentinel@<version> --version` returns the new version.

### Step 11: Deploy web (if packages/web changed)
```bash
pnpm deploy:web
```
Verify the live registry reflects the new version.

### Step 12: Post-release
- Update `agent_docs/product-milestones.md` — mark completed deliverables as `[x]`
- Update the Known Issues section in root `CLAUDE.md` if bugs were resolved

## Version Semantics for MCP Sentinel
| Change Type | Version Bump |
|-------------|-------------|
| New detection rule (no engine change) | patch |
| New detection rule (new engine handler) | minor |
| New crawler source | patch |
| API endpoint added | minor |
| API endpoint changed (breaking) | major |
| Database schema migration | major |
| Rule removed or renamed | major |
