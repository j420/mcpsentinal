/**
 * accuracy/target-loader.ts
 *
 * Loads and validates `rules/accuracy-targets.yaml`. Every active detection
 * rule declares a `target_precision`, `target_recall`, and `rationale`. The
 * accuracy dashboard compares measured metrics against these targets to gate
 * Rule Accuracy Audit regressions.
 *
 * The YAML schema is intentionally small — a sidecar file (not per-rule
 * fields) was chosen so the targets stay in one auditable document and
 * don't pollute the 164 rule YAMLs.
 */
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_TARGETS_PATH = resolve(
  __dirname,
  "../../../../rules/accuracy-targets.yaml"
);

// ── Zod schema ──────────────────────────────────────────────────────────────

/** Per-rule target entry. `target_recall: null` means "not applicable" (e.g. companion stubs). */
const RuleTargetSchema = z.object({
  target_precision: z.number().min(0).max(1),
  target_recall: z.number().min(0).max(1).nullable(),
  rationale: z.string().min(1),
});

const DefaultTargetSchema = z.object({
  target_precision: z.number().min(0).max(1),
  target_recall: z.number().min(0).max(1),
});

const AccuracyTargetsSchema = z.object({
  version: z.literal(1),
  last_updated: z.string(),
  default: DefaultTargetSchema,
  rules: z.record(z.string(), RuleTargetSchema),
});

export type RuleTarget = z.infer<typeof RuleTargetSchema>;
export type AccuracyTargets = z.infer<typeof AccuracyTargetsSchema>;

// ── Loader ──────────────────────────────────────────────────────────────────

let cachedTargets: AccuracyTargets | null = null;
let cachedPath: string | null = null;

/**
 * Load the accuracy-targets.yaml manifest from disk.
 *
 * @param path - absolute path override, defaults to repo-root `rules/accuracy-targets.yaml`
 */
export function loadAccuracyTargets(path: string = DEFAULT_TARGETS_PATH): AccuracyTargets {
  if (cachedTargets && cachedPath === path) return cachedTargets;
  if (!existsSync(path)) {
    throw new Error(`accuracy-targets.yaml not found at ${path}`);
  }
  const raw = parseYaml(readFileSync(path, "utf-8"));
  const parsed = AccuracyTargetsSchema.parse(raw);
  cachedTargets = parsed;
  cachedPath = path;
  return parsed;
}

/**
 * Get the target for a single rule. Falls back to the manifest `default` if
 * the rule is not declared — this is a safety net and should never fire in
 * practice (every active rule must have an entry).
 */
export function getTargetFor(
  ruleId: string,
  targets: AccuracyTargets
): RuleTarget {
  const entry = targets.rules[ruleId];
  if (entry) return entry;
  return {
    target_precision: targets.default.target_precision,
    target_recall: targets.default.target_recall,
    rationale: `(falling back to default — no explicit target declared for ${ruleId})`,
  };
}

/**
 * Return the set of rule IDs that have explicit target entries.
 */
export function getDeclaredRuleIds(targets: AccuracyTargets): Set<string> {
  return new Set(Object.keys(targets.rules));
}

/** Exported for tests — forces the next loadAccuracyTargets call to re-read disk. */
export function resetTargetsCache(): void {
  cachedTargets = null;
  cachedPath = null;
}
