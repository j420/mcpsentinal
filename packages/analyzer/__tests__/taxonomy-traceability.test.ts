/**
 * Taxonomy Traceability Guard
 *
 * Verifies that `rules/taxonomy/attack-vectors.yaml` is a faithful, exhaustive
 * cover of every active rule and that the rule-methodology manifest
 * (`tools/scripts/build-rule-methodology.ts`) agrees with the analyzer's
 * implementation directories.
 *
 * Why this guard is here (and not in the API package):
 *
 *   - The taxonomy is the API contract for the new "Deep Dive as hero" detail
 *     page. Drift between the taxonomy and the rule registry would silently
 *     hide rules from the UI's posture matrix.
 *   - The methodology manifest is consumed by the API as a static file. We
 *     run the same builder used by `pnpm build:methodology` against the
 *     working tree so a misplaced or missing CHARTER fails CI HERE, not at
 *     deploy time.
 *
 * Hard guarantees enforced:
 *
 *   1. Every active rule_id (YAML enabled: true) appears in EXACTLY one
 *      sub-category (canonical placement) in attack-vectors.yaml.
 *   2. Every retired rule_id (YAML enabled: false) appears in retired_rules
 *      and NEVER in any sub-category.
 *   3. No sub-category has zero rules.
 *   4. Every cross_reference rule_id is canonically placed somewhere else
 *      (not in the same sub-category, never dangling).
 *   5. Every category id and sub-category id is kebab-case, unique within
 *      its scope, and stable.
 *   6. The methodology manifest covers every active rule; severities and
 *      techniques are valid; no missing CHARTER, no missing index.
 */

import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

// Mirror the validation enums from `tools/scripts/build-rule-methodology.ts`.
// Kept inline (rather than imported) so the test can run inside this package
// without resolving `yaml` against the repo-root tools/ path — the build
// script imports `yaml` from the workspace and is exercised below by running
// it as a subprocess and parsing the manifest JSON it writes.
const VALID_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;
const VALID_TECHNIQUES = [
  "ast-taint",
  "capability-graph",
  "schema-inference",
  "entropy",
  "similarity",
  "linguistic",
  "unicode",
  "structural",
  "dependency-audit",
  "cross-module",
  "composite",
  "stub",
] as const;

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const TAXONOMY_PATH = join(REPO_ROOT, "rules", "taxonomy", "attack-vectors.yaml");
const RULES_YAML_DIR = join(REPO_ROOT, "rules");

interface SubCategory {
  id: string;
  title: string;
  summary: string;
  rule_ids: string[];
  cross_references?: string[];
}

interface Category {
  id: string;
  title: string;
  summary: string;
  frameworks: string[];
  sub_categories: SubCategory[];
}

interface RetiredEntry {
  id: string;
  reason: string;
}

interface AttackVectorTaxonomy {
  version: number;
  generated_at: string;
  categories: Category[];
  retired_rules: RetiredEntry[];
}

interface RuleMetadata {
  id: string;
  enabled: boolean;
}

// Manifest shape — mirrors `tools/scripts/build-rule-methodology.ts`.
interface ManifestRule {
  id: string;
  name: string;
  severity: string;
  category: string;
  technique: string | null;
  interface_version: string | null;
  remediation: string;
  threat_refs: { id: string; kind: string }[];
}
interface Manifest {
  version: string;
  generated_at: string;
  rules: Record<string, ManifestRule>;
  retired: Record<string, { id: string; name: string; category: string }>;
  missing_charter: string[];
  missing_index: string[];
  errors: { rule_id: string; message: string }[];
}
function parseManifest(raw: unknown): Manifest {
  // Defensive cast — the script writes a deterministic shape; this just
  // narrows the type for the test body.
  return raw as Manifest;
}

const KEBAB_CASE = (s: string): boolean => /^[a-z][a-z0-9-]*[a-z0-9]$/.test(s);

function loadTaxonomy(): AttackVectorTaxonomy {
  return parseYaml(readFileSync(TAXONOMY_PATH, "utf8")) as AttackVectorTaxonomy;
}

function loadActiveAndRetiredRuleIds(): {
  active: Set<string>;
  retired: Set<string>;
} {
  const active = new Set<string>();
  const retired = new Set<string>();
  for (const name of readdirSync(RULES_YAML_DIR)) {
    if (!name.endsWith(".yaml")) continue;
    if (name === "framework-registry.yaml") continue;
    const meta = parseYaml(
      readFileSync(join(RULES_YAML_DIR, name), "utf8"),
    ) as RuleMetadata;
    if (!meta?.id) continue;
    if (meta.enabled === false) retired.add(meta.id);
    else active.add(meta.id);
  }
  return { active, retired };
}

describe("attack-vector taxonomy", () => {
  const taxonomy = loadTaxonomy();
  const { active: activeRuleIds, retired: retiredRuleIds } =
    loadActiveAndRetiredRuleIds();

  it("declares contract version 1", () => {
    expect(taxonomy.version).toBe(1);
  });

  it("has exactly 13 top-level risk-domain categories", () => {
    expect(taxonomy.categories).toHaveLength(13);
  });

  it("category ids and sub-category ids are kebab-case and unique", () => {
    const categoryIds = new Set<string>();
    const subCategoryIds = new Map<string, Set<string>>();
    for (const cat of taxonomy.categories) {
      expect(KEBAB_CASE(cat.id), `category id "${cat.id}" not kebab-case`).toBe(true);
      expect(categoryIds.has(cat.id), `duplicate category id "${cat.id}"`).toBe(false);
      categoryIds.add(cat.id);

      const subIds = new Set<string>();
      for (const sub of cat.sub_categories) {
        expect(
          KEBAB_CASE(sub.id),
          `sub-category id "${cat.id}/${sub.id}" not kebab-case`,
        ).toBe(true);
        expect(
          subIds.has(sub.id),
          `duplicate sub-category id "${cat.id}/${sub.id}"`,
        ).toBe(false);
        subIds.add(sub.id);
      }
      subCategoryIds.set(cat.id, subIds);
    }
  });

  it("every category has 4–7 sub-categories (briefing range)", () => {
    for (const cat of taxonomy.categories) {
      expect(
        cat.sub_categories.length,
        `${cat.id} has ${cat.sub_categories.length} sub-categories`,
      ).toBeGreaterThanOrEqual(4);
      expect(
        cat.sub_categories.length,
        `${cat.id} has ${cat.sub_categories.length} sub-categories`,
      ).toBeLessThanOrEqual(7);
    }
  });

  it("every sub-category has at least one rule", () => {
    for (const cat of taxonomy.categories) {
      for (const sub of cat.sub_categories) {
        expect(
          sub.rule_ids.length,
          `${cat.id}/${sub.id} has zero canonical rules`,
        ).toBeGreaterThan(0);
      }
    }
  });

  it("every active rule has exactly one canonical placement", () => {
    const placements = new Map<string, string>();
    const duplicates: string[] = [];
    for (const cat of taxonomy.categories) {
      for (const sub of cat.sub_categories) {
        for (const ruleId of sub.rule_ids) {
          const key = `${cat.id}/${sub.id}`;
          if (placements.has(ruleId)) {
            duplicates.push(`${ruleId}: ${placements.get(ruleId)} + ${key}`);
          } else {
            placements.set(ruleId, key);
          }
        }
      }
    }
    expect(duplicates).toEqual([]);

    // Every active rule placed
    const missing: string[] = [];
    for (const id of activeRuleIds) {
      if (!placements.has(id)) missing.push(id);
    }
    expect(missing, "active rules not placed in any sub-category").toEqual([]);

    // Nothing extra placed
    const extra: string[] = [];
    for (const id of placements.keys()) {
      if (!activeRuleIds.has(id)) extra.push(id);
    }
    expect(extra, "rule_ids placed canonically that are not active").toEqual([]);
  });

  it("retired rules appear ONLY in retired_rules (never canonically placed)", () => {
    expect(taxonomy.retired_rules.length).toBe(retiredRuleIds.size);
    const retiredInTaxonomy = new Set(taxonomy.retired_rules.map((r) => r.id));
    expect(retiredInTaxonomy).toEqual(retiredRuleIds);

    const placedRetired: string[] = [];
    for (const cat of taxonomy.categories) {
      for (const sub of cat.sub_categories) {
        for (const id of sub.rule_ids) {
          if (retiredRuleIds.has(id)) placedRetired.push(`${cat.id}/${sub.id}/${id}`);
        }
      }
    }
    expect(placedRetired, "retired rules found in sub-categories").toEqual([]);
  });

  it("every retired_rules entry has a non-empty reason", () => {
    for (const r of taxonomy.retired_rules) {
      expect(typeof r.reason).toBe("string");
      expect(r.reason.trim().length).toBeGreaterThan(0);
    }
  });

  it("every cross_reference resolves to a canonical placement elsewhere", () => {
    // Build canonical placements first.
    const placements = new Map<string, string>();
    for (const cat of taxonomy.categories) {
      for (const sub of cat.sub_categories) {
        for (const id of sub.rule_ids) {
          placements.set(id, `${cat.id}/${sub.id}`);
        }
      }
    }

    const unresolved: string[] = [];
    for (const cat of taxonomy.categories) {
      for (const sub of cat.sub_categories) {
        const here = `${cat.id}/${sub.id}`;
        for (const xref of sub.cross_references ?? []) {
          if (!placements.has(xref)) {
            unresolved.push(`${here} cross-refs ${xref} which is not canonically placed`);
            continue;
          }
          if (placements.get(xref) === here) {
            unresolved.push(`${here} cross-refs ${xref} which is canonically here (self-ref)`);
          }
        }
      }
    }
    expect(unresolved).toEqual([]);
  });

  it("every category has at least one framework reference", () => {
    for (const cat of taxonomy.categories) {
      expect(cat.frameworks.length, `${cat.id} has no framework refs`).toBeGreaterThan(0);
    }
  });

  it("category and sub-category summaries are non-empty", () => {
    for (const cat of taxonomy.categories) {
      expect(cat.summary.trim().length, `${cat.id} summary empty`).toBeGreaterThan(0);
      for (const sub of cat.sub_categories) {
        expect(
          sub.summary.trim().length,
          `${cat.id}/${sub.id} summary empty`,
        ).toBeGreaterThan(0);
      }
    }
  });
});

describe("rule-methodology manifest", () => {
  // Re-exercise the build script as a subprocess. This is intentional: the
  // script imports `yaml` from the workspace at the repo-root tools/ path,
  // which is not directly resolvable from this test file's transform context.
  // Running it as the same `tsx`-driven CLI invocation that `pnpm
  // build:methodology` uses guarantees the test catches the same failure
  // modes deploy will see.
  //
  // The script writes `data/rule-methodology.json` and exits non-zero on
  // any error — so a non-zero exit here is itself the test failure.
  const scriptPath = resolve(REPO_ROOT, "tools", "scripts", "build-rule-methodology.ts");
  const tsxBin = resolve(
    REPO_ROOT,
    "node_modules",
    ".pnpm",
    "node_modules",
    ".bin",
    "tsx",
  );
  // Fall back to the workspace tsx if the .pnpm-mirrored bin is not present.
  const tsx = existsSync(tsxBin)
    ? tsxBin
    : resolve(REPO_ROOT, "node_modules", ".bin", "tsx");

  let manifest: ReturnType<typeof parseManifest>;
  try {
    execFileSync(tsx, [scriptPath], {
      cwd: REPO_ROOT,
      stdio: "pipe",
      env: process.env,
    });
  } catch (err) {
    const e = err as { stderr?: Buffer | string; stdout?: Buffer | string; message?: string };
    const stderr = typeof e.stderr === "string" ? e.stderr : e.stderr?.toString("utf8") ?? "";
    const stdout = typeof e.stdout === "string" ? e.stdout : e.stdout?.toString("utf8") ?? "";
    throw new Error(
      `build-rule-methodology.ts exited non-zero.\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}\n`,
    );
  }
  const manifestPath = resolve(REPO_ROOT, "data", "rule-methodology.json");
  manifest = parseManifest(JSON.parse(readFileSync(manifestPath, "utf8")));

  const { active: activeRuleIds, retired: retiredRuleIds } =
    loadActiveAndRetiredRuleIds();

  it("has version 1 and a generated_at timestamp", () => {
    expect(manifest.version).toBe("1");
    expect(typeof manifest.generated_at).toBe("string");
    expect(manifest.generated_at.length).toBeGreaterThan(0);
  });

  it("covers every active rule and only active rules", () => {
    const manifestActive = new Set(Object.keys(manifest.rules));
    const missing = [...activeRuleIds].filter((id) => !manifestActive.has(id));
    const extra = [...manifestActive].filter((id) => !activeRuleIds.has(id));
    expect(missing, "active rules missing from manifest").toEqual([]);
    expect(extra, "manifest entries that are not active rules").toEqual([]);
  });

  it("retired entries match the YAML-disabled set", () => {
    const manifestRetired = new Set(Object.keys(manifest.retired));
    expect(manifestRetired).toEqual(retiredRuleIds);
  });

  it("reports zero missing-charter and zero missing-index entries", () => {
    expect(manifest.missing_charter).toEqual([]);
    expect(manifest.missing_index).toEqual([]);
  });

  it("reports no errors", () => {
    expect(manifest.errors).toEqual([]);
  });

  it("every rule has a valid severity", () => {
    const valid = new Set<string>(VALID_SEVERITIES);
    for (const r of Object.values(manifest.rules)) {
      expect(valid.has(r.severity), `${r.id} severity "${r.severity}" invalid`).toBe(true);
    }
  });

  it("every rule has a valid AnalysisTechnique", () => {
    const valid = new Set<string>(VALID_TECHNIQUES);
    for (const r of Object.values(manifest.rules)) {
      expect(r.technique, `${r.id} technique not parsed from index.ts`).not.toBeNull();
      expect(
        valid.has(r.technique as string),
        `${r.id} technique "${r.technique}" not in AnalysisTechnique union`,
      ).toBe(true);
    }
  });

  it("every rule declares interface_version v2", () => {
    for (const r of Object.values(manifest.rules)) {
      expect(r.interface_version, `${r.id} interface_version`).toBe("v2");
    }
  });

  it("every rule has a non-empty remediation", () => {
    for (const r of Object.values(manifest.rules)) {
      expect(r.remediation.trim().length, `${r.id} remediation empty`).toBeGreaterThan(0);
    }
  });

  it("every rule has at least one threat reference", () => {
    for (const r of Object.values(manifest.rules)) {
      expect(r.threat_refs.length, `${r.id} has no threat_refs`).toBeGreaterThan(0);
    }
  });
});
