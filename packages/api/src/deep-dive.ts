/**
 * Deep Dive aggregate (Cluster D part 2 of 5).
 *
 * Powers `GET /api/v1/servers/:slug/deep-dive`. Bundles taxonomy +
 * methodology + per-server findings + framework cross-walk + detection-
 * quality into ONE round-trip so the Deep Dive page (Cluster D agents
 * 3/4/5) issues exactly one fetch.
 *
 * This module is deliberately I/O-free at the helper boundary — the route
 * handler in `server.ts` does the DB fetch + the index priming, then calls
 * `buildDeepDive()` with all inputs in hand. That keeps the helper trivial
 * to test (no fs / pg / red-team mocks needed) and lets the loaders be
 * memoised at module scope.
 *
 * Why a separate file (mirrors `compliance-matrix.ts`, `detection-quality.ts`,
 * `risk-boundary.ts`, `drift.ts`):
 *   - Pure helper module pattern keeps `server.ts` declarative.
 *   - Memoised lazy loaders for the taxonomy YAML + methodology JSON are
 *     module-local (built on first request, then O(1) per request).
 *   - Tests exercise the helper without booting Express.
 *   - The honest-gap fallbacks (taxonomy missing, analysis-coverage missing,
 *     methodology missing) live in one place where they can be reasoned
 *     about together — not scattered across the route handler.
 *
 * Honest-gap rules (every rule, evidence-first):
 *   - findings.length > 0  → status: "findings"
 *   - findings.length == 0 + rule has its required inputs → status: "passed"
 *   - findings.length == 0 + rule needed inputs we did NOT have for this
 *     server (e.g. C-rules without source code) → status: "skipped"
 *
 * The skip-reason derivation requires the analyzer's coverage report. When
 * coverage is unavailable for this server, fall back to the honest-pessimism
 * default: any rule with no findings → "passed". This pessimism is
 * explicitly documented because it can OVER-CLAIM passes for rules that
 * actually had no input — but every alternative either invents data or
 * silently hides rules. Logging once at the route layer (not here) flags
 * the fallback for ops.
 *
 * Route-collision audit (PR #218 lesson — extends the audit doctrine):
 *   - `/api/v1/servers/:slug/deep-dive` does not appear anywhere in
 *     `packages/web/src/`. Verified by grepping for both `deep-dive` and
 *     `deep_dive` — zero matches under web.
 *   - The path has 4 segments (servers / :slug / deep-dive); no existing
 *     route is shaped `:slug/:something/deep-dive` and there is no
 *     `/deep-dive/:framework`, so route collisions are structurally
 *     impossible against the current surface.
 *   - Express matches in declaration order. The route handler MUST be
 *     declared after `/findings` and before any catch-all (the same
 *     position pattern PR #218 fixed for `/compliance-summary`).
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pino from "pino";

// Module-local logger — Cluster D reviewer M3 lesson. Loader failures
// emit a single warn line so production ops sees the signal instead of
// silently serving categories: []. Stderr-bound (matches the rest of
// the api package's pino config).
const _logger = pino({ name: "api:deep-dive" }, process.stderr);
import type {
  DeepDiveCategory,
  DeepDiveCoverage,
  DeepDiveFinding,
  DeepDiveMethodology,
  DeepDiveResponse,
  DeepDiveRule,
  DeepDiveRuleStatus,
  DeepDiveSeverityBreakdown,
  DeepDiveSubCategory,
  DetectionQuality,
  Finding,
  FrameworkControlMapping,
  Server,
  Severity,
} from "@mcp-sentinel/database";

// ─── Taxonomy + Methodology types (loader contracts) ───────────────────────

/**
 * The shape of `rules/taxonomy/attack-vectors.yaml` (Agent 1 deliverable).
 *
 * The loader normalises Agent 1's exact YAML keys into this shape. Unknown
 * fields are preserved through the response via `.passthrough()` schemas
 * upstream. The loader is intentionally lenient: missing fields collapse
 * to safe defaults rather than throwing.
 */
export interface TaxonomyShape {
  categories: TaxonomyCategory[];
}

export interface TaxonomyCategory {
  id: string;
  title: string;
  summary: string;
  frameworks: string[];
  sub_categories: TaxonomySubCategory[];
}

export interface TaxonomySubCategory {
  id: string;
  title: string;
  summary: string;
  /** Rule IDs (e.g. ["A1", "A9", "B5"]). Order is rendered verbatim. */
  rules: string[];
}

/**
 * The shape of `data/rule-methodology.json` (Agent 1 deliverable). One
 * entry per rule_id. Fields mirror the relevant CHARTER.md sections.
 *
 * `rule_meta` is the registry-level rule metadata snapshot (name, severity,
 * owasp, mitre, category, remediation) — duplicated into the methodology
 * file so this helper does NOT need to re-load every rule's YAML on each
 * request.
 */
export interface MethodologyManifest {
  [ruleId: string]: MethodologyEntry;
}

export interface MethodologyEntry {
  technique: string;
  verified_edge_cases: string[];
  edge_case_strategies: string[];
  confidence_cap: number | null;
  /** "what it detects" sentence derived from CHARTER. */
  summary: string;
  rule_meta: {
    name: string;
    severity: Severity;
    /** Legacy letter category, e.g. "code-analysis" → letter "C". */
    category: string;
    owasp: string | null;
    mitre: string | null;
    remediation: string;
    /**
     * Inputs this rule needs to run. Used to compute the "skipped" status
     * when the analyzer's coverage report is available. Each value is
     * compared against the analyzer's `analysis_coverage` flags:
     *   - "source_code"   maps to had_source_code
     *   - "connection"    maps to had_connection
     *   - "dependencies"  maps to had_dependencies
     * Unknown values are ignored (honest pessimism — counts as "no skip").
     */
    requires_inputs?: ReadonlyArray<"source_code" | "connection" | "dependencies">;
  };
}

// ─── Path resolution (mirrors detection-quality.ts) ─────────────────────────

function defaultTaxonomyPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // src/ → packages/api/ → packages/ → repo
  return resolve(here, "..", "..", "..", "rules", "taxonomy", "attack-vectors.yaml");
}

function defaultMethodologyPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, "..", "..", "..", "data", "rule-methodology.json");
}

// ─── Memoised loaders ───────────────────────────────────────────────────────
// Both loaders are: lazy (first call), memoised (subsequent are O(1)),
// graceful (fs / parse / dependency failures degrade to empty). The pattern
// mirrors detection-quality.ts:80-87 and compliance-matrix.ts.
//
// Empty taxonomy is a legitimate state (Agent 1's deliverable not yet in
// the worktree, missing in the production image, etc.) — the response
// degrades to `{server, coverage, categories: []}` and the frontend
// renders an explicit "taxonomy unavailable" panel.

let _taxonomyPromise: Promise<TaxonomyShape | null> | null = null;
let _methodologyPromise: Promise<MethodologyManifest | null> | null = null;

/**
 * Load + memoise the taxonomy YAML. Returns null on any failure
 * (file missing, YAML parser unavailable, parse error). The route
 * handler treats null as "no taxonomy on file" → empty `categories[]`
 * in the response.
 *
 * Cluster D reviewer B2 — `yaml` is now a direct dep of `packages/api`
 * (added in this PR). The dynamic specifier remains for forward-compat
 * with pnpm hoisting changes. Reviewer M3 — failures emit a pino warn
 * line so production ops sees the signal instead of silently serving
 * empty categories.
 */
export function loadTaxonomy(): Promise<TaxonomyShape | null> {
  if (!_taxonomyPromise) {
    _taxonomyPromise = (async () => {
      try {
        const raw = readFileSync(defaultTaxonomyPath(), "utf-8");
        const yamlSpecifier: string = "yaml";
        const yamlMod = (await import(/* @vite-ignore */ yamlSpecifier).catch(
          (err) => {
            _logger.warn(
              { err: String(err) },
              "deep-dive: yaml import failed — degrading to categories:[]",
            );
            return null;
          },
        )) as { parse?: (text: string) => unknown } | null;
        if (!yamlMod || typeof yamlMod.parse !== "function") return null;
        const parsed = yamlMod.parse(raw);
        const normalised = normaliseTaxonomy(parsed);
        if (!normalised || normalised.categories.length === 0) {
          _logger.warn(
            { path: defaultTaxonomyPath() },
            "deep-dive: taxonomy parsed but contains zero categories",
          );
        }
        return normalised;
      } catch (err) {
        _logger.warn(
          { err: String(err), path: defaultTaxonomyPath() },
          "deep-dive: failed to load taxonomy — degrading to categories:[]",
        );
        return null;
      }
    })();
  }
  return _taxonomyPromise;
}

/**
 * Load + memoise the methodology JSON. Returns null on any failure.
 *
 * Cluster D reviewer B3/B4 — `data/rule-methodology.json` is wrapped
 * in `{version, generated_at, rules: { ... }, retired, ...}` (the Agent 1
 * extractor's shape). We unwrap to the inner `rules` map AND project
 * each flat entry into the `MethodologyEntry` shape the assembler
 * expects (renaming `lethal_edge_cases` → `verified_edge_cases`,
 * promoting flat rule fields under `rule_meta`).
 *
 * Reviewer M3 — failures emit a pino warn.
 */
export function loadRuleMethodology(): Promise<MethodologyManifest | null> {
  if (!_methodologyPromise) {
    _methodologyPromise = (async () => {
      try {
        const raw = readFileSync(defaultMethodologyPath(), "utf-8");
        const parsed = JSON.parse(raw) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          _logger.warn(
            "deep-dive: rule-methodology.json is not a JSON object — degrading",
          );
          return null;
        }
        const projected = projectMethodologyManifest(parsed);
        if (!projected || Object.keys(projected).length === 0) {
          _logger.warn(
            { path: defaultMethodologyPath() },
            "deep-dive: rule-methodology.json had zero rules after projection",
          );
        }
        return projected;
      } catch (err) {
        _logger.warn(
          { err: String(err), path: defaultMethodologyPath() },
          "deep-dive: failed to load rule-methodology.json — degrading",
        );
        return null;
      }
    })();
  }
  return _methodologyPromise;
}

/**
 * Project the on-disk extractor format to the loader's `MethodologyEntry`
 * shape. Cluster D reviewer B4 — the extractor (Agent 1's
 * `tools/scripts/build-rule-methodology.ts`) emits flat entries with
 * `lethal_edge_cases`; the loader/assembler want `verified_edge_cases`
 * AND a nested `rule_meta`. The projection happens here so neither side
 * needs to change.
 *
 * Tolerant: missing fields degrade to defaults (empty arrays, null).
 * Fields not on the extractor (`summary`, `requires_inputs`) stay
 * empty — surfaced as "methodology not fully on file" in the UI.
 */
function projectMethodologyManifest(parsed: unknown): MethodologyManifest | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const root = parsed as Record<string, unknown>;
  const rulesField = root["rules"];
  if (!rulesField || typeof rulesField !== "object" || Array.isArray(rulesField)) {
    return null;
  }
  const out: MethodologyManifest = {};
  for (const [ruleId, rawEntry] of Object.entries(rulesField as Record<string, unknown>)) {
    if (!rawEntry || typeof rawEntry !== "object") continue;
    const e = rawEntry as Record<string, unknown>;
    const technique = typeof e["technique"] === "string" ? (e["technique"] as string) : "unspecified";
    const verified = Array.isArray(e["lethal_edge_cases"])
      ? (e["lethal_edge_cases"] as unknown[]).filter((s): s is string => typeof s === "string")
      : Array.isArray(e["verified_edge_cases"])
        ? (e["verified_edge_cases"] as unknown[]).filter((s): s is string => typeof s === "string")
        : [];
    const strategies = Array.isArray(e["edge_case_strategies"])
      ? (e["edge_case_strategies"] as unknown[]).filter((s): s is string => typeof s === "string")
      : [];
    const confidenceCap =
      typeof e["confidence_cap"] === "number" ? (e["confidence_cap"] as number) : null;
    const severityRaw = e["severity"];
    const allowedSev: Severity[] = ["critical", "high", "medium", "low", "informational"];
    const severity: Severity = allowedSev.includes(severityRaw as Severity)
      ? (severityRaw as Severity)
      : "informational";
    out[ruleId] = {
      technique,
      verified_edge_cases: verified,
      edge_case_strategies: strategies,
      confidence_cap: confidenceCap,
      summary: typeof e["summary"] === "string" ? (e["summary"] as string) : "",
      rule_meta: {
        name: typeof e["name"] === "string" ? (e["name"] as string) : ruleId,
        severity,
        category: typeof e["category"] === "string" ? (e["category"] as string) : "",
        owasp: typeof e["owasp"] === "string" ? (e["owasp"] as string) : null,
        mitre: typeof e["mitre"] === "string" ? (e["mitre"] as string) : null,
        remediation: typeof e["remediation"] === "string" ? (e["remediation"] as string) : "",
      },
    };
  }
  return out;
}

// ─── Test-only helpers ─────────────────────────────────────────────────────
// Underscore prefix so these are clearly NOT part of the public surface.

export function _resetDeepDiveLoadersForTests(): void {
  _taxonomyPromise = null;
  _methodologyPromise = null;
}

export function _setTaxonomyForTests(value: TaxonomyShape | null): void {
  _taxonomyPromise = Promise.resolve(value);
}

export function _setMethodologyForTests(value: MethodologyManifest | null): void {
  _methodologyPromise = Promise.resolve(value);
}

// ─── Taxonomy normaliser ────────────────────────────────────────────────────
// Tolerant — Agent 1's exact YAML key names may differ slightly from the
// internal contract. We accept the documented shape; we drop entries that
// don't have an id + at least one sub-category with rules.
function normaliseTaxonomy(parsed: unknown): TaxonomyShape | null {
  if (!parsed || typeof parsed !== "object") return null;
  const root = parsed as Record<string, unknown>;
  const cats = root["categories"];
  if (!Array.isArray(cats)) return null;
  const normalised: TaxonomyCategory[] = [];
  for (const c of cats) {
    if (!c || typeof c !== "object") continue;
    const r = c as Record<string, unknown>;
    const id = typeof r["id"] === "string" ? r["id"] : null;
    if (!id) continue;
    const subs = Array.isArray(r["sub_categories"]) ? r["sub_categories"] : [];
    const subNormalised: TaxonomySubCategory[] = [];
    for (const s of subs) {
      if (!s || typeof s !== "object") continue;
      const sr = s as Record<string, unknown>;
      const sid = typeof sr["id"] === "string" ? sr["id"] : null;
      if (!sid) continue;
      // Cluster D reviewer B2 — the YAML uses `rule_ids` (canonical
      // placements), not `rules`. The prior `sr["rules"]` lookup
      // produced empty arrays for every sub-category, dropping the
      // entire taxonomy at line 279. Fix: read `rule_ids` AND
      // `cross_references` (reviewer m2) so secondary placements also
      // populate the cross-reference map.
      const canonicalRules = Array.isArray(sr["rule_ids"])
        ? (sr["rule_ids"] as unknown[]).filter((x): x is string => typeof x === "string")
        : [];
      const crossRefRules = Array.isArray(sr["cross_references"])
        ? (sr["cross_references"] as unknown[]).filter((x): x is string => typeof x === "string")
        : [];
      // Concatenate canonical + cross-reference rule ids so every rule
      // listed under this sub-category in the YAML appears here. The
      // assembler's `ruleAppearances` map then sees the full list and
      // produces correct `cross_referenced_in[]` entries.
      const rules = [...canonicalRules, ...crossRefRules];
      subNormalised.push({
        id: sid,
        title: typeof sr["title"] === "string" ? sr["title"] : sid,
        summary: typeof sr["summary"] === "string" ? sr["summary"] : "",
        rules,
      });
    }
    if (subNormalised.length === 0) continue;
    const frameworks = Array.isArray(r["frameworks"])
      ? (r["frameworks"] as unknown[]).filter((x): x is string => typeof x === "string")
      : [];
    normalised.push({
      id,
      title: typeof r["title"] === "string" ? r["title"] : id,
      summary: typeof r["summary"] === "string" ? r["summary"] : "",
      frameworks,
      sub_categories: subNormalised,
    });
  }
  return { categories: normalised };
}

// ─── Builder ────────────────────────────────────────────────────────────────

export interface BuildDeepDiveInput {
  server: Pick<Server, "slug" | "name">;
  findings: Finding[];
  taxonomy: TaxonomyShape | null;
  methodology: MethodologyManifest | null;
  /**
   * The analyzer's per-scan coverage report. When available, drives the
   * "skipped" status for rules whose required inputs were not present
   * (e.g. C-rules with no source code).
   *
   * When null, every rule with no findings degrades to "passed". Honest-
   * pessimism documented at the top of this file.
   */
  coverage: AnalysisCoverageInput | null;
  /**
   * Reverse index from `compliance-matrix.ts`. Looks up
   * `Array<FrameworkControlMapping>` per rule_id. Pass an empty function
   * (returns []) to opt out of the cross-walk.
   */
  getFrameworkControls: (ruleId: string) => FrameworkControlMapping[];
  /**
   * Reverse index from `detection-quality.ts`. Looks up `DetectionQuality`
   * (or null) per rule_id. Pass a function that always returns null to
   * opt out of the per-rule backing footer.
   */
  getDetectionQuality: (ruleId: string) => DetectionQuality | null;
}

export interface AnalysisCoverageInput {
  had_source_code: boolean;
  had_connection: boolean;
  had_dependencies: boolean;
  rules_executed: number;
  rules_skipped_no_data: number;
  coverage_band: "high" | "medium" | "low" | "minimal" | null;
}

/**
 * Pure, deterministic deep-dive assembly. Idempotent: same inputs always
 * produce byte-equivalent output. The route handler is the only place
 * with side effects (DB fetch, fs read).
 */
export function buildDeepDive(input: BuildDeepDiveInput): DeepDiveResponse {
  const findingsByRule = groupFindingsByRule(input.findings);

  // No taxonomy on file → honest-gap response. categories[] = []. The page
  // renders a "taxonomy unavailable" placeholder. coverage still populates
  // from findings + (optional) analysis_coverage so the hero still works.
  if (!input.taxonomy || input.taxonomy.categories.length === 0) {
    return {
      server: { slug: input.server.slug, name: input.server.name },
      coverage: assembleCoverage({
        coverage: input.coverage,
        findings: input.findings,
        totalRulesInTaxonomy: 0,
        rulesWithFindings: countDistinctRules(findingsByRule),
      }),
      categories: [],
    };
  }

  // Track which rules we've placed under a category — used to compute
  // `cross_referenced_in` when a rule appears in multiple sub-categories.
  // First pass: discover every (categoryId, subCategoryId) a rule appears in.
  const ruleAppearances = new Map<string, Array<{ category_id: string; sub_category_id: string }>>();
  for (const cat of input.taxonomy.categories) {
    for (const sub of cat.sub_categories) {
      for (const ruleId of sub.rules) {
        let bucket = ruleAppearances.get(ruleId);
        if (!bucket) {
          bucket = [];
          ruleAppearances.set(ruleId, bucket);
        }
        bucket.push({ category_id: cat.id, sub_category_id: sub.id });
      }
    }
  }

  // Build categories.
  const categories: DeepDiveCategory[] = input.taxonomy.categories.map((cat) =>
    assembleCategory({
      cat,
      findingsByRule,
      methodology: input.methodology,
      coverage: input.coverage,
      ruleAppearances,
      getFrameworkControls: input.getFrameworkControls,
      getDetectionQuality: input.getDetectionQuality,
    }),
  );

  const totalRulesInTaxonomy = ruleAppearances.size;
  const rulesWithFindings = countDistinctRules(findingsByRule);

  return {
    server: { slug: input.server.slug, name: input.server.name },
    coverage: assembleCoverage({
      coverage: input.coverage,
      findings: input.findings,
      totalRulesInTaxonomy,
      rulesWithFindings,
    }),
    categories,
  };
}

// ─── Internal assembly ──────────────────────────────────────────────────────

function groupFindingsByRule(findings: Finding[]): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>();
  for (const f of findings) {
    const id = f.rule_id;
    let bucket = m.get(id);
    if (!bucket) {
      bucket = [];
      m.set(id, bucket);
    }
    bucket.push(f);
  }
  return m;
}

function countDistinctRules(findingsByRule: Map<string, Finding[]>): number {
  return findingsByRule.size;
}

interface AssembleCategoryInput {
  cat: TaxonomyCategory;
  findingsByRule: Map<string, Finding[]>;
  methodology: MethodologyManifest | null;
  coverage: AnalysisCoverageInput | null;
  ruleAppearances: Map<string, Array<{ category_id: string; sub_category_id: string }>>;
  getFrameworkControls: (ruleId: string) => FrameworkControlMapping[];
  getDetectionQuality: (ruleId: string) => DetectionQuality | null;
}

function assembleCategory(input: AssembleCategoryInput): DeepDiveCategory {
  const subCategories: DeepDiveSubCategory[] = input.cat.sub_categories.map((sub) =>
    assembleSubCategory({
      cat: input.cat,
      sub,
      findingsByRule: input.findingsByRule,
      methodology: input.methodology,
      coverage: input.coverage,
      ruleAppearances: input.ruleAppearances,
      getFrameworkControls: input.getFrameworkControls,
      getDetectionQuality: input.getDetectionQuality,
    }),
  );

  // Roll up sub-category counts to category counts.
  const counts = sumSubCategoryCounts(subCategories);

  return {
    id: input.cat.id,
    title: input.cat.title,
    summary: input.cat.summary,
    frameworks: [...input.cat.frameworks],
    counts,
    sub_categories: subCategories,
  };
}

interface AssembleSubCategoryInput extends AssembleCategoryInput {
  sub: TaxonomySubCategory;
}

function assembleSubCategory(input: AssembleSubCategoryInput): DeepDiveSubCategory {
  const rules: DeepDiveRule[] = input.sub.rules.map((ruleId) =>
    assembleRule({
      ruleId,
      categoryId: input.cat.id,
      subCategoryId: input.sub.id,
      findingsByRule: input.findingsByRule,
      methodology: input.methodology,
      coverage: input.coverage,
      ruleAppearances: input.ruleAppearances,
      getFrameworkControls: input.getFrameworkControls,
      getDetectionQuality: input.getDetectionQuality,
    }),
  );
  const counts = computeRuleCounts(rules);

  return {
    id: input.sub.id,
    title: input.sub.title,
    summary: input.sub.summary,
    counts,
    rules,
  };
}

interface AssembleRuleInput {
  ruleId: string;
  categoryId: string;
  subCategoryId: string;
  findingsByRule: Map<string, Finding[]>;
  methodology: MethodologyManifest | null;
  coverage: AnalysisCoverageInput | null;
  ruleAppearances: Map<string, Array<{ category_id: string; sub_category_id: string }>>;
  getFrameworkControls: (ruleId: string) => FrameworkControlMapping[];
  getDetectionQuality: (ruleId: string) => DetectionQuality | null;
}

function assembleRule(input: AssembleRuleInput): DeepDiveRule {
  const found = input.findingsByRule.get(input.ruleId) ?? [];
  const methodologyEntry = input.methodology?.[input.ruleId];

  // status derivation:
  //   findings present       → "findings"
  //   coverage missing       → "passed" (honest pessimism — see file header)
  //   coverage present + the rule's required inputs were available → "passed"
  //   coverage present + a required input was missing → "skipped"
  const status: DeepDiveRuleStatus = deriveStatus(
    found.length,
    methodologyEntry,
    input.coverage,
  );

  // Cross-references: only emit when the rule appears in MORE THAN one
  // (category, sub_category) pair AND the OTHER pairs (i.e. not the one
  // we're currently building under).
  const appearances = input.ruleAppearances.get(input.ruleId) ?? [];
  const otherAppearances = appearances.filter(
    (a) => !(a.category_id === input.categoryId && a.sub_category_id === input.subCategoryId),
  );

  // Methodology fallback when the manifest is missing this rule. We render
  // an empty methodology block so the contract shape is stable; the page
  // renders an explicit "methodology not on file" pill rather than hiding.
  const methodology: DeepDiveMethodology = methodologyEntry
    ? {
        technique: methodologyEntry.technique,
        verified_edge_cases: [...methodologyEntry.verified_edge_cases],
        edge_case_strategies: [...methodologyEntry.edge_case_strategies],
        confidence_cap: methodologyEntry.confidence_cap,
      }
    : {
        technique: "unspecified",
        verified_edge_cases: [],
        edge_case_strategies: [],
        confidence_cap: null,
      };

  // Rule meta — sourced from methodology.rule_meta when present;
  // otherwise we use neutral placeholders so the contract is intact.
  const meta = methodologyEntry?.rule_meta;
  const findings: DeepDiveFinding[] = found.map((f) => ({
    id: f.id,
    severity: f.severity,
    confidence: f.confidence,
    evidence: f.evidence,
    evidence_chain: f.evidence_chain ?? null,
    remediation: f.remediation,
  }));

  const rule: DeepDiveRule = {
    rule_id: input.ruleId,
    name: meta?.name ?? input.ruleId,
    severity: meta?.severity ?? deriveSeverityFromFindings(found) ?? "informational",
    category: meta?.category ?? deriveLetterCategory(input.ruleId),
    owasp: meta?.owasp ?? null,
    mitre: meta?.mitre ?? null,
    summary: methodologyEntry?.summary ?? "",
    framework_controls: input.getFrameworkControls(input.ruleId),
    methodology,
    backing: input.getDetectionQuality(input.ruleId),
    remediation: meta?.remediation ?? deriveRemediationFromFindings(found),
    status,
    findings,
  };
  if (otherAppearances.length > 0) {
    rule.cross_referenced_in = otherAppearances;
  }
  return rule;
}

// ─── Status derivation ──────────────────────────────────────────────────────

function deriveStatus(
  findingCount: number,
  methodologyEntry: MethodologyEntry | undefined,
  coverage: AnalysisCoverageInput | null,
): DeepDiveRuleStatus {
  if (findingCount > 0) return "findings";
  // No findings — was the rule even run?
  if (!coverage) return "passed"; // honest-pessimism fallback
  const required = methodologyEntry?.rule_meta.requires_inputs ?? [];
  for (const need of required) {
    if (need === "source_code" && !coverage.had_source_code) return "skipped";
    if (need === "connection" && !coverage.had_connection) return "skipped";
    if (need === "dependencies" && !coverage.had_dependencies) return "skipped";
  }
  return "passed";
}

// ─── Counts ─────────────────────────────────────────────────────────────────

function emptySeverityBreakdown(): DeepDiveSeverityBreakdown {
  return { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
}

function bumpSeverity(b: DeepDiveSeverityBreakdown, sev: Severity): void {
  // The Severity enum is closed; the cast is type-safe at the boundary
  // because Severity is `"critical" | "high" | … | "informational"` and
  // every member is a key of DeepDiveSeverityBreakdown (the `5` entries).
  (b as Record<string, number>)[sev] = ((b as Record<string, number>)[sev] ?? 0) + 1;
}

function computeRuleCounts(rules: DeepDiveRule[]): {
  rules_total: number;
  rules_passed: number;
  rules_with_findings: number;
  rules_skipped: number;
  finding_count: number;
  severity_breakdown: DeepDiveSeverityBreakdown;
} {
  let passed = 0;
  let withFindings = 0;
  let skipped = 0;
  let findingCount = 0;
  const sev = emptySeverityBreakdown();
  for (const r of rules) {
    if (r.status === "passed") passed++;
    else if (r.status === "findings") withFindings++;
    else skipped++;
    findingCount += r.findings.length;
    for (const f of r.findings) bumpSeverity(sev, f.severity);
  }
  return {
    rules_total: rules.length,
    rules_passed: passed,
    rules_with_findings: withFindings,
    rules_skipped: skipped,
    finding_count: findingCount,
    severity_breakdown: sev,
  };
}

function sumSubCategoryCounts(subs: DeepDiveSubCategory[]): {
  rules_total: number;
  rules_passed: number;
  rules_with_findings: number;
  rules_skipped: number;
  finding_count: number;
  severity_breakdown: DeepDiveSeverityBreakdown;
} {
  let total = 0;
  let passed = 0;
  let withFindings = 0;
  let skipped = 0;
  let findingCount = 0;
  const sev = emptySeverityBreakdown();
  for (const s of subs) {
    total += s.counts.rules_total;
    passed += s.counts.rules_passed;
    withFindings += s.counts.rules_with_findings;
    skipped += s.counts.rules_skipped;
    findingCount += s.counts.finding_count;
    sev.critical += s.counts.severity_breakdown.critical;
    sev.high += s.counts.severity_breakdown.high;
    sev.medium += s.counts.severity_breakdown.medium;
    sev.low += s.counts.severity_breakdown.low;
    sev.informational += s.counts.severity_breakdown.informational;
  }
  return {
    rules_total: total,
    rules_passed: passed,
    rules_with_findings: withFindings,
    rules_skipped: skipped,
    finding_count: findingCount,
    severity_breakdown: sev,
  };
}

interface AssembleCoverageInput {
  coverage: AnalysisCoverageInput | null;
  findings: Finding[];
  totalRulesInTaxonomy: number;
  rulesWithFindings: number;
}

function assembleCoverage(input: AssembleCoverageInput): DeepDiveCoverage {
  const sev = emptySeverityBreakdown();
  for (const f of input.findings) bumpSeverity(sev, f.severity);
  return {
    coverage_band: input.coverage?.coverage_band ?? null,
    total_rules: input.totalRulesInTaxonomy,
    rules_executed: input.coverage?.rules_executed ?? 0,
    rules_skipped_no_data: input.coverage?.rules_skipped_no_data ?? 0,
    rules_with_findings: input.rulesWithFindings,
    total_findings: input.findings.length,
    severity_breakdown: sev,
  };
}

// ─── Last-resort fallbacks ──────────────────────────────────────────────────
// Used only when methodology is missing for a rule. The contract requires
// non-null severity / category / remediation; these synthesize honest-but-
// neutral placeholders. The empty severity_breakdown stays correct because
// these only fire when there are no methodology metadata to use anyway.

function deriveSeverityFromFindings(findings: Finding[]): Severity | null {
  // Highest-seen severity wins. This is a last-resort fallback — when
  // methodology is on file, the rule's declared severity is used instead.
  const order: Severity[] = ["critical", "high", "medium", "low", "informational"];
  for (const sev of order) {
    if (findings.some((f) => f.severity === sev)) return sev;
  }
  return null;
}

function deriveRemediationFromFindings(findings: Finding[]): string {
  if (findings.length === 0) return "";
  // Use the first finding's remediation — the database guarantees every
  // Finding row has a remediation string.
  return findings[0]!.remediation;
}

function deriveLetterCategory(ruleId: string): string {
  // "C12" → "C", "K20" → "K". Unknown shapes degrade to "unknown".
  const m = ruleId.match(/^[A-Z]/);
  return m ? m[0] : "unknown";
}
