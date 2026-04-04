# MCP Sentinel Change Map (Engineering + Compliance)

This runbook maps common change requests to the exact packages, files, and verification steps required to implement them safely.

Use this when making product, detection, API, reporting, or compliance-impacting changes.

---

## 1) Non-Negotiable Invariants

Before touching code, preserve these constraints:

1. **No live MCP tool invocation in standard scanning paths**  
   Scanning must remain `initialize` + `tools/list` only.  
   Dynamic invocation is separately gated and auditable.

2. **Deterministic detection pipeline**  
   Detection logic is implemented in TypeScript TypedRules; YAML is metadata.

3. **Evidence-first findings contract**  
   Findings must include `rule_id`, evidence, and remediation.

4. **Append-only analytics mindset**  
   Historical/security trend reporting depends on immutable history tables and persisted runs.

5. **Documentation constants must be synchronized**  
   Publicly visible constants (e.g., rule count) must match scanner/analyzer reality across README, package docs, and badges.

---

## 2) Source-of-Truth Index

| Concern | Canonical Location(s) | Notes |
|---|---|---|
| Top-level scripts and workflow commands | `package.json` (root) | `crawl`, `scan`, `score`, `risk-matrix`, `attack-graph`, `red-team`, `dynamic-test` |
| Workspace/package boundaries | `pnpm-workspace.yaml`, `packages/*` | Monorepo composition |
| Build/test orchestration | `turbo.json` | Build dependency graph and task behavior |
| Rule metadata registry | `rules/*.yaml` | Metadata only |
| Detection engine conventions | `CLAUDE.md` + `packages/analyzer/*` | Typed rule expectations and constraints |
| DB schema/migrations | `packages/database/src/migrate.ts` | Shared contract for API/reporting/scoring |
| Public API behavior | `packages/api/src/server.ts` | Validation, response formats, rate limits |
| Ecosystem reporting | `packages/reports/src/*` | Trend/category/overview report generation |
| Cross-server risk analysis | `packages/risk-matrix/src/*` | Pattern detection P01–P12 |
| Kill-chain synthesis | `packages/attack-graph/src/*` | Multi-step chain generation |

### CI / Actions Trigger Awareness (Before Opening a PR)

Not every PR change set triggers the same GitHub Actions workflows.

| Workflow | Trigger | Practical implication for contributors |
|---|---|---|
| `ci.yml` | `pull_request` to `main` **only when paths match code/config globs** | Docs-only edits (e.g., `README.md`, `docs/**`) do **not** trigger this workflow unless CI workflow files or tracked code/config paths also change. |
| `crawl.yml` | `workflow_dispatch`, weekly schedule | Not PR-triggered; operational crawl pipeline. |
| `scan.yml` | `workflow_dispatch`, `workflow_run` after crawl completion on `main` | Not PR-triggered; pipeline execution depends on crawl or manual dispatch. |
| `accuracy.yml` | manual dispatch (schedule currently disabled) | Not PR-triggered by default. |
| `publish.yml` | semver tag push | Release-time only, never PR-time. |

**Reviewer checklist for trigger correctness**
1. Confirm whether your PR path set is expected to run `ci.yml`.
2. If CI is expected but did not run, verify changed files match `ci.yml` `on.pull_request.paths`.
3. For docs-only PRs, run local validation commands explicitly and include outputs in PR notes.

---

## 3) Task-to-Change Matrix

### A. Add/Modify Detection Rule

**Edit surface**
- `rules/<rule>.yaml` (metadata)
- `packages/analyzer/src/rules/implementations/*` (logic)
- `packages/analyzer/src/rules/index.ts` (registration)
- `packages/analyzer/__tests__/*` (at least TP/TN coverage)

**Flow**
1. Add/adjust YAML metadata with stable ID/severity/remediation.
2. Implement or update TypedRule.
3. Register rule in analyzer index.
4. Add/update tests (true positives, true negatives, and confidence/evidence assertions).
5. Re-run scanner path smoke test using representative fixture/config.

**Edge cases to test**
- Evasion strings (unicode/encoded instructions).
- False positive resistance on safe API usage.
- Partial metadata/tool schema input.
- Cross-file and cross-tool context where relevant.

---

### B. Change Scoring Behavior

**Edit surface**
- `packages/scorer/src/*`
- Score consumption points in API/reporting where score assumptions are encoded
- Documentation on scoring interpretation

**Flow**
1. Update scoring computation.
2. Validate score bounds and category penalties.
3. Re-run scorer tests and dependent integration checks.
4. Regenerate/spot-check score-dependent outputs in API and reports.
5. Update docs to prevent mismatch in operator guidance.

**Edge cases**
- All-critical findings (floor behavior).
- No-findings clean server (ceiling behavior).
- Sparse categories and missing dimensions.
- Historic trend continuity after scoring updates.

---

### C. API Contract Change (new field/filter/endpoint)

**Edit surface**
- `packages/api/src/server.ts`
- `packages/database/src/queries.ts` (or related DB accessor)
- API tests in package-level test suite
- Web/UI consumers if exposed publicly

**Flow**
1. Define request/response contract and validate input with Zod.
2. Implement DB retrieval logic and pagination/filter behavior.
3. Add route tests for happy path + invalid input + rate-limit/error paths.
4. Verify no sensitive data leakage in logs and responses.
5. Update docs/examples/cURL snippets.

**Edge cases**
- Invalid slugs and path traversal attempts.
- Empty/oversized filter sets.
- Extremely high-cardinality search result pages.
- Caching/ETag behavior for SVG or frequently fetched endpoints.

---

### D. Add Crawler Source / Modify Discovery

**Edit surface**
- `packages/crawler/src/orchestrator.ts` and source adapters
- Crawl persistence paths in database package
- Operational docs/runbooks for source assumptions/limits

**Flow**
1. Implement source connector with deterministic normalization.
2. Ensure per-source metrics are emitted.
3. Validate dedup/canonical ID behavior.
4. Run dry-run crawl and then persistence test against local DB.
5. Confirm downstream scan picks up newly discovered servers.

**Edge cases**
- Duplicate records across registries.
- Source throttling/timeouts and retry boundaries.
- Partial metadata from source APIs.
- Identifier poisoning (malformed URLs/packages).

---

### E. Compliance/Framework-Wide Reporting Enhancement

**Edit surface**
- `packages/reports/src/ecosystem-stats.ts`
- `packages/reports/src/trend-analysis.ts`
- `packages/reports/src/category-breakdown.ts`
- `packages/reports/src/generator.ts`
- Optional: DB queries or schema support

**Flow**
1. Define regulator-facing metric (e.g., control coverage, severity exposure, time-to-remediate trend).
2. Add deterministic SQL-backed aggregation.
3. Render in markdown report with methodology and denominator clarity.
4. Add consistency checks for percent calculations and zero-denominator paths.
5. Version stamp the report and archive output artifacts.

**Edge cases**
- Null/missing category fields.
- Very small sample sizes (misleading percentages).
- Cross-period comparability (schema drift).
- Rule-set expansion impact on trend interpretation.

---

## 4) Credibility Guardrails (Do Before Merge)

1. **Contract checks**
   - API schema compatibility for existing clients.
   - Stable CLI output semantics where used by CI/GitHub Action.

2. **Evidence quality checks**
   - Findings include actionable remediation and concrete evidence.
   - No “opaque” findings that cannot be audited by operators.

3. **Security regressions**
   - Input validation still enforced for all externally reachable API routes.
   - Logging does not include secrets or unsafe untrusted control characters.

4. **Documentation parity**
   - Rule counts and major capability claims aligned across:
     - root README
     - scanner package README
     - badges/examples

5. **Operational readiness**
   - Commands in docs are runnable as documented.
   - Migrations and reporting scripts verified with representative data.

---

## 5) Recommended Validation Commands

Run from repository root:

```bash
pnpm test
pnpm typecheck
pnpm build
pnpm crawl -- --dry-run
pnpm scan -- --dry-run --limit=25 --json
pnpm risk-matrix -- --dry-run --limit=500 --json
pnpm attack-graph -- --dry-run --limit=500 --json
DATABASE_URL=... pnpm --filter=@mcp-sentinel/reports run generate -- --json
```

If changing only docs/constants, at minimum run targeted consistency checks:

```bash
rg -n "103|60-rule|detection_rules-103" README.md packages/mcp-sentinel-scanner/README.md CLAUDE.md
```

---

## 6) “Do Not Ship” Checklist

Do not merge if any of the below are true:

- Public rule-count claims differ across major docs or package metadata.
- API route behavior changed without validation and error-path tests.
- New findings lack evidence/remediation fields.
- Cross-server analyses fail on empty datasets or large `--limit` values.
- Reporting metrics cannot explain denominators or data sources.

---

## 7) Suggested Ownership Model

- **Detection correctness owner:** analyzer + rules + scorer
- **Platform/data owner:** crawler + connector + database
- **Surface/API owner:** api + web + action
- **Assurance owner:** reports + risk-matrix + attack-graph + red-team

Each PR should identify which owner domain(s) it touches and include explicit validation for those domains.

