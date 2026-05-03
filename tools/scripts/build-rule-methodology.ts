#!/usr/bin/env tsx
/**
 * Build Rule Methodology Manifest — Cluster D
 *
 * Walks `packages/analyzer/src/rules/implementations/<rule-id>/` and emits a
 * single JSON manifest at `data/rule-methodology.json` covering every rule
 * registered in the analyzer. The output is keyed by rule_id and merges:
 *
 *   - YAML metadata from `rules/<RULE>-<kebab>.yaml`
 *     (id, name, severity, category, owasp, mitre, remediation)
 *
 *   - CHARTER frontmatter from `<rule-dir>/CHARTER.md`
 *     (interface_version, threat_refs, lethal_edge_cases,
 *      edge_case_strategies, evidence_contract, confidence_cap if declared)
 *
 *   - Implementation `technique` declared in `<rule-dir>/index.ts`
 *     (the `readonly technique: AnalysisTechnique = "..."` declaration)
 *
 * The output is consumed by the API layer (Cluster D part 4) at static-file
 * read time — same access pattern as `docs/accuracy/latest.json`.
 *
 * Run:
 *
 *   pnpm build:methodology
 *
 *   # or directly:
 *   pnpm tsx tools/scripts/build-rule-methodology.ts
 *
 * Validation contract (mirrored by `__tests__/taxonomy-traceability.test.ts`):
 *
 *   - every active rule in the YAML registry MUST have a CHARTER.md and
 *     an index.ts with a parsable `technique` declaration
 *   - severity values MUST be one of {critical, high, medium, low, informational}
 *   - technique values MUST be one of the AnalysisTechnique union members
 *   - rules with `enabled: false` in YAML are skipped (retired) and recorded
 *     in the manifest's `retired` block
 *
 * No regex literals on rule data — we parse YAML with the workspace `yaml`
 * package and use a single light line-scan extractor for the `technique`
 * declaration (mirrors how `charter-traceability.test.ts` extracts the
 * `RULE_ID`).
 */

import {
  readFileSync,
  readdirSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  statSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const RULES_YAML_DIR = join(REPO_ROOT, "rules");
const IMPL_ROOT = join(
  REPO_ROOT,
  "packages",
  "analyzer",
  "src",
  "rules",
  "implementations",
);
const OUTPUT_DIR = join(REPO_ROOT, "data");
const OUTPUT_PATH = join(OUTPUT_DIR, "rule-methodology.json");

// ─── Allowed severity / technique enums ─────────────────────────────────────

export const VALID_SEVERITIES = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;
export type Severity = (typeof VALID_SEVERITIES)[number];

export const VALID_TECHNIQUES = [
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
export type AnalysisTechnique = (typeof VALID_TECHNIQUES)[number];

// ─── Output shape ───────────────────────────────────────────────────────────

export interface ThreatRef {
  kind: string;
  id: string;
  url: string | null;
  summary: string | null;
}

export interface EvidenceContract {
  minimum_chain: {
    source: boolean;
    propagation: boolean;
    sink: boolean;
    mitigation: boolean;
    impact: boolean;
  };
  required_factors: string[];
  location_kinds: string[];
}

export interface RuleMethodology {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  owasp: string | null;
  mitre: string | null;
  remediation: string;
  enabled: boolean;
  interface_version: string | null;
  technique: AnalysisTechnique | null;
  confidence_cap: number | null;
  lethal_edge_cases: string[];
  edge_case_strategies: string[];
  evidence_contract: EvidenceContract | null;
  threat_refs: ThreatRef[];
  /**
   * Phase 1.2 — declared input requirements parsed from the rule's
   * `readonly requires: RuleRequirements = { ... }` declaration in
   * `index.ts`. Consumed by the deep-dive endpoint's `deriveStatus` to
   * decide whether a rule is "passed" (ran with all inputs available) or
   * "skipped" (a required input was missing for this server). Without
   * this field, every findingless rule defaults to "passed" — silently
   * misleading for rules that needed source code or live connection
   * data we did not have.
   *
   * Empty array means the rule is always-applicable (declares no input
   * requirements) — should never be classified as "skipped" for missing
   * data even if the server lacks source / connection / dependencies.
   */
  requires_inputs: string[];
  /**
   * Phase 1.2 — short human-readable summary of what this rule detects.
   * Sourced from the first `true_positive` test case description in the
   * YAML metadata. Test cases are mandatory so this field is reliably
   * non-empty for active rules. Falls back to the rule name when test
   * cases are absent or malformed.
   *
   * Used by the deep-dive page to render a one-line description per
   * rule. The previous default of "" caused every rule to render with
   * no description — observed in production.
   */
  summary: string;
}

export interface RetiredRule {
  id: string;
  name: string;
  category: string;
  owasp: string | null;
  mitre: string | null;
}

export interface Manifest {
  version: string;
  generated_at: string;
  rules: Record<string, RuleMethodology>;
  retired: Record<string, RetiredRule>;
  missing_charter: string[];
  missing_index: string[];
  errors: { rule_id: string; message: string }[];
}

// ─── Discovery: rule directories ────────────────────────────────────────────

interface RuleDirEntry {
  rule_id: string;
  dir_path: string;
}

function listRuleDirs(): RuleDirEntry[] {
  if (!existsSync(IMPL_ROOT)) return [];
  const out: RuleDirEntry[] = [];
  for (const name of readdirSync(IMPL_ROOT)) {
    if (name.startsWith("_")) continue; // _shared, _bench, etc.
    const full = join(IMPL_ROOT, name);
    const st = statSync(full);
    if (!st.isDirectory()) continue;
    const indexPath = join(full, "index.ts");
    if (!existsSync(indexPath)) continue;
    const ruleId = extractRuleId(indexPath);
    if (ruleId) out.push({ rule_id: ruleId, dir_path: full });
  }
  return out;
}

/**
 * Light line-scan extractor for the rule id declared in <ruleDir>/index.ts.
 * Mirrors the strategy used by `charter-traceability.test.ts` so the two
 * stay aligned — supports:
 *   - const RULE_ID = "K1"; readonly id = RULE_ID;
 *   - readonly id = "K1";
 *   - id: "K1"
 *   - public readonly id: string = "K1";
 */
function extractRuleId(indexPath: string): string | null {
  const text = readFileSync(indexPath, "utf8");
  const lines = text.split("\n");
  const constStrings = new Map<string, string>();
  for (const line of lines) {
    const trimmed = line.trim();
    const m = trimmed.match(/^(?:export\s+)?const\s+([A-Z_][A-Z0-9_]*)\s*=\s*"([^"]+)"/);
    if (m) constStrings.set(m[1], m[2]);
  }
  for (const line of lines) {
    const trimmed = line.trim();
    const lit = trimmed.match(/\bid\s*[:=]\s*"([A-Q]\d+)"/);
    if (lit) return lit[1];
    const ref = trimmed.match(/\bid\s*[:=]\s*([A-Z_][A-Z0-9_]*)\b/);
    if (ref && constStrings.has(ref[1])) return constStrings.get(ref[1]) ?? null;
  }
  return null;
}

/**
 * Parse `readonly technique: AnalysisTechnique = "structural";` style
 * declarations. Same strategy as extractRuleId — single-line property
 * declaration with a string literal RHS.
 */
function extractTechnique(indexPath: string): string | null {
  const text = readFileSync(indexPath, "utf8");
  const lines = text.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    const m = trimmed.match(/\btechnique\s*[:=][^"]*"([a-z][a-z0-9-]*)"/);
    if (m) return m[1];
  }
  return null;
}

/**
 * Extract the `readonly requires: RuleRequirements = { ... }` declaration
 * from a rule's index.ts and return the list of input keys the rule
 * declares as required. Handles both single-line and multi-line shapes:
 *
 *   readonly requires: RuleRequirements = { source_code: true };
 *
 *   readonly requires: RuleRequirements = {
 *     source_code: true,
 *     dependencies: true,
 *     min_tools: 10,
 *   };
 *
 * The valid keys mirror `RuleRequirements` at
 * `packages/analyzer/src/rules/base.ts:62-85`. Boolean keys with `true`
 * are emitted verbatim (e.g. `source_code`); the numeric `min_tools`
 * key is emitted as `min_tools(N)` so downstream consumers can render
 * "needs >10 tools" without a second extraction pass.
 *
 * Returns [] when no requires declaration is parseable — a rule with no
 * declared inputs is always-applicable and should not be classified as
 * "skipped" for missing data.
 */
function extractRequiresInputs(indexPath: string): string[] {
  const text = readFileSync(indexPath, "utf8");
  const start = text.indexOf("readonly requires");
  if (start < 0) return [];
  const openBrace = text.indexOf("{", start);
  if (openBrace < 0) return [];
  // Walk forward to find the matching closing brace, respecting nested braces.
  let depth = 0;
  let close = -1;
  for (let i = openBrace; i < text.length; i++) {
    const c = text[i];
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) {
        close = i;
        break;
      }
    }
  }
  if (close < 0) return [];
  const body = text.slice(openBrace + 1, close);

  const out: string[] = [];
  // Boolean inputs: `source_code: true`, `dependencies: true`, etc.
  // Only `true` matters — `false` declarations don't require the input.
  for (const m of body.matchAll(/\b([a-z_][a-z0-9_]*)\s*:\s*true\b/gi)) {
    out.push(m[1]);
  }
  // Numeric guard: `min_tools: 10`. Render as "min_tools(10)" so the
  // downstream gap message is honest about the threshold.
  for (const m of body.matchAll(/\bmin_tools\s*:\s*(\d+)\b/g)) {
    out.push(`min_tools(${m[1]})`);
  }
  // Deduplicate while preserving order — a rule might declare the same
  // key twice through copy-paste; the manifest should not double-count.
  return Array.from(new Set(out));
}

// ─── CHARTER.md frontmatter parsing ─────────────────────────────────────────

interface CharterRaw {
  rule_id?: string;
  interface_version?: string;
  severity?: string;
  threat_refs?: Array<{ kind?: string; id?: string; url?: string; summary?: string }>;
  lethal_edge_cases?: string[];
  edge_case_strategies?: string[];
  evidence_contract?: {
    minimum_chain?: {
      source?: boolean;
      propagation?: boolean;
      sink?: boolean;
      mitigation?: boolean;
      impact?: boolean;
    };
    required_factors?: string[];
    location_kinds?: string[];
  };
  confidence_cap?: number | string;
  obsolescence?: { retire_when?: string };
}

function parseFrontmatter(charterPath: string): CharterRaw | null {
  const text = readFileSync(charterPath, "utf8");
  const lines = text.split("\n");
  if (lines[0]?.trim() !== "---") return null;
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === "---");
  if (end < 0) return null;
  const yamlText = lines.slice(1, end).join("\n");
  try {
    return parseYaml(yamlText) as CharterRaw;
  } catch {
    return null;
  }
}

// ─── YAML metadata ──────────────────────────────────────────────────────────

interface RuleYaml {
  id?: string;
  name?: string;
  category?: string;
  severity?: string;
  owasp?: string | null;
  mitre?: string | null;
  remediation?: string;
  enabled?: boolean;
  /**
   * Test cases declared under `test_cases.true_positive[]`. Each entry has
   * a `description` field that is — by repository convention — a one-line
   * concrete example of what the rule fires on. The first such description
   * is the closest thing to a machine-derivable rule summary.
   */
  test_cases?: {
    true_positive?: Array<{ description?: string; expected?: boolean }>;
    true_negative?: Array<{ description?: string; expected?: boolean }>;
  };
}

/**
 * Build the human-readable summary for a rule. Prefers the first
 * true_positive test case description (concise, concrete, always
 * present in the YAML). Falls back to the rule name when test cases
 * are absent/empty so the page never renders an empty description.
 */
function deriveSummary(yaml: RuleYaml): string {
  const positives = yaml.test_cases?.true_positive ?? [];
  for (const tc of positives) {
    if (typeof tc?.description === "string" && tc.description.trim().length > 0) {
      return tc.description.trim();
    }
  }
  return (yaml.name ?? "").trim();
}

function loadAllRuleYamls(): Map<string, RuleYaml> {
  const map = new Map<string, RuleYaml>();
  if (!existsSync(RULES_YAML_DIR)) return map;
  for (const name of readdirSync(RULES_YAML_DIR)) {
    if (!name.endsWith(".yaml")) continue;
    if (name === "framework-registry.yaml") continue;
    const full = join(RULES_YAML_DIR, name);
    let data: unknown;
    try {
      data = parseYaml(readFileSync(full, "utf8"));
    } catch {
      continue;
    }
    if (!data || typeof data !== "object") continue;
    const yaml = data as RuleYaml;
    if (!yaml.id) continue;
    map.set(yaml.id, yaml);
  }
  return map;
}

// ─── Build manifest ─────────────────────────────────────────────────────────

export function buildManifest(): Manifest {
  const yamlByRuleId = loadAllRuleYamls();
  const ruleDirs = listRuleDirs();
  const ruleDirsByRuleId = new Map<string, string>();
  for (const r of ruleDirs) ruleDirsByRuleId.set(r.rule_id, r.dir_path);

  const manifest: Manifest = {
    version: "1",
    generated_at: new Date().toISOString(),
    rules: {},
    retired: {},
    missing_charter: [],
    missing_index: [],
    errors: [],
  };

  for (const [ruleId, yaml] of yamlByRuleId) {
    if (yaml.enabled === false) {
      // Retired rule — record minimal entry, do not require CHARTER/index.
      manifest.retired[ruleId] = {
        id: ruleId,
        name: yaml.name ?? ruleId,
        category: yaml.category ?? "unknown",
        owasp: yaml.owasp ?? null,
        mitre: yaml.mitre ?? null,
      };
      continue;
    }

    // Active rule — must have a directory + CHARTER + parsable technique.
    const dirPath = ruleDirsByRuleId.get(ruleId) ?? null;
    if (!dirPath) {
      manifest.missing_index.push(ruleId);
      manifest.errors.push({
        rule_id: ruleId,
        message: "no implementation directory under packages/analyzer/src/rules/implementations/",
      });
      continue;
    }

    const indexPath = join(dirPath, "index.ts");
    const charterPath = join(dirPath, "CHARTER.md");

    let charter: CharterRaw | null = null;
    if (!existsSync(charterPath)) {
      manifest.missing_charter.push(ruleId);
    } else {
      charter = parseFrontmatter(charterPath);
      if (charter === null) {
        manifest.errors.push({
          rule_id: ruleId,
          message: `CHARTER.md frontmatter could not be parsed at ${charterPath}`,
        });
      }
    }

    const technique = extractTechnique(indexPath);
    if (technique === null) {
      manifest.errors.push({
        rule_id: ruleId,
        message: `no technique declaration found in ${indexPath}`,
      });
    } else if (!(VALID_TECHNIQUES as readonly string[]).includes(technique)) {
      manifest.errors.push({
        rule_id: ruleId,
        message: `technique "${technique}" is not a valid AnalysisTechnique`,
      });
    }

    const severity = (yaml.severity ?? "").toLowerCase();
    if (!(VALID_SEVERITIES as readonly string[]).includes(severity)) {
      manifest.errors.push({
        rule_id: ruleId,
        message: `severity "${yaml.severity}" is not a valid Severity`,
      });
    }

    const evidenceContract = charter?.evidence_contract
      ? {
          minimum_chain: {
            source: !!charter.evidence_contract.minimum_chain?.source,
            propagation: !!charter.evidence_contract.minimum_chain?.propagation,
            sink: !!charter.evidence_contract.minimum_chain?.sink,
            mitigation: !!charter.evidence_contract.minimum_chain?.mitigation,
            impact: !!charter.evidence_contract.minimum_chain?.impact,
          },
          required_factors: Array.isArray(charter.evidence_contract.required_factors)
            ? charter.evidence_contract.required_factors.slice()
            : [],
          location_kinds: Array.isArray(charter.evidence_contract.location_kinds)
            ? charter.evidence_contract.location_kinds.slice()
            : [],
        }
      : null;

    const threatRefs: ThreatRef[] = Array.isArray(charter?.threat_refs)
      ? (charter!.threat_refs as ThreatRef[]).map((r) => ({
          kind: r.kind ?? "unknown",
          id: r.id ?? "unknown",
          url: r.url ?? null,
          summary: typeof r.summary === "string" ? r.summary.trim() : null,
        }))
      : [];

    const confidenceCap =
      charter && typeof charter.confidence_cap === "number"
        ? charter.confidence_cap
        : charter && typeof charter.confidence_cap === "string"
          ? Number.parseFloat(charter.confidence_cap)
          : null;

    manifest.rules[ruleId] = {
      id: ruleId,
      name: yaml.name ?? ruleId,
      severity: (severity as Severity) || "informational",
      category: yaml.category ?? "unknown",
      owasp: yaml.owasp ?? null,
      mitre: yaml.mitre ?? null,
      remediation: yaml.remediation ?? "",
      enabled: yaml.enabled !== false,
      interface_version: charter?.interface_version ?? null,
      technique:
        technique && (VALID_TECHNIQUES as readonly string[]).includes(technique)
          ? (technique as AnalysisTechnique)
          : null,
      confidence_cap:
        typeof confidenceCap === "number" && Number.isFinite(confidenceCap)
          ? confidenceCap
          : null,
      lethal_edge_cases: Array.isArray(charter?.lethal_edge_cases)
        ? (charter!.lethal_edge_cases as unknown[])
            .filter((s): s is string => typeof s === "string")
            .map((s) => s.trim())
        : [],
      edge_case_strategies: Array.isArray(charter?.edge_case_strategies)
        ? (charter!.edge_case_strategies as unknown[])
            .filter((s): s is string => typeof s === "string")
            .map((s) => s.trim())
        : [],
      evidence_contract: evidenceContract,
      threat_refs: threatRefs,
      // Phase 1.2 — required inputs parsed from `readonly requires` in
      // index.ts, and a one-line summary derived from the first
      // true_positive test case description.
      requires_inputs: extractRequiresInputs(indexPath),
      summary: deriveSummary(yaml),
    };
  }

  return manifest;
}

// ─── CLI entry ──────────────────────────────────────────────────────────────

function main(): void {
  const manifest = buildManifest();
  if (!existsSync(OUTPUT_DIR)) mkdirSync(OUTPUT_DIR, { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify(manifest, null, 2) + "\n", "utf8");

  const activeCount = Object.keys(manifest.rules).length;
  const retiredCount = Object.keys(manifest.retired).length;
  const errCount = manifest.errors.length;

  // eslint-disable-next-line no-console
  console.log(
    `[build-rule-methodology] wrote ${OUTPUT_PATH} — ${activeCount} active, ` +
      `${retiredCount} retired, ${errCount} errors, ` +
      `${manifest.missing_charter.length} missing-charter, ` +
      `${manifest.missing_index.length} missing-index`,
  );
  if (errCount > 0) {
    for (const e of manifest.errors) {
      // eslint-disable-next-line no-console
      console.error(`  ! ${e.rule_id}: ${e.message}`);
    }
    process.exit(1);
  }
}

const isEntry = (() => {
  try {
    return resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
})();
if (isEntry) main();
