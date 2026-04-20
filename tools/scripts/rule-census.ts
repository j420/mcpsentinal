#!/usr/bin/env tsx
/**
 * Rule Census — Phase 0, Chunk 0.1
 *
 * Produces a machine-readable + human-readable snapshot of every detection
 * rule's current state: registration, detector file, and AST-observed
 * technique usage. Writes:
 *
 *   docs/census/<YYYY-MM-DD>.json   full CensusRow[] + summary
 *   docs/census/latest.md           rank-ordered, human-readable table
 *
 * This is the baseline that Phase 1's per-rule migrations are measured
 * against. Runtime behavior is NOT modified — this script only reads.
 *
 * Why AST-observed and not self-declared? Rules currently declare a
 * `technique` (e.g. "structural"), but that declaration is not enforced.
 * A rule can claim "structural" while containing 26 regex literals. The
 * census reads the source and reports what's actually there.
 *
 * Usage:
 *   pnpm tsx tools/scripts/rule-census.ts
 *   pnpm tsx tools/scripts/rule-census.ts --json-only
 *   pnpm tsx tools/scripts/rule-census.ts --date 2026-04-20
 */

import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, relative, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";
import * as ts from "typescript";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const RULES_YAML_DIR = join(REPO_ROOT, "rules");
const DETECTOR_DIR = join(
  REPO_ROOT,
  "packages",
  "analyzer",
  "src",
  "rules",
  "implementations",
);
const CENSUS_DIR = join(REPO_ROOT, "docs", "census");

// ─── Types ──────────────────────────────────────────────────────────────────

export interface TechniqueObservations {
  regex_literals: number;
  new_regexp_calls: number;
  string_arrays_over_5: number;
  ts_compiler_api_import: boolean;
  tree_sitter_import: boolean;
  uses_taint_ast: boolean;
  uses_capability_graph: boolean;
  uses_module_graph: boolean;
  uses_entropy: boolean;
  uses_similarity: boolean;
  uses_schema_inference: boolean;
  uses_evidence_chain_builder: boolean;
}

export interface CensusRow {
  rule_id: string;
  name: string | null;
  category: string | null;
  severity: string | null;
  enabled: boolean;
  yaml_detect_type: string | null;
  yaml_engine_v2: boolean;
  registered_v1: boolean;
  registered_v2: boolean;
  detector_file: string | null;
  technique_observed: TechniqueObservations | null;
  notes: string[];
}

export interface CensusSummary {
  generated_at: string;
  total_yaml_rules: number;
  enabled_yaml_rules: number;
  registered_rules: number;
  registered_v1: number;
  registered_v2: number;
  unregistered_enabled: number;
  detectors: {
    total_files: number;
    files_with_any_regex: number;
    files_with_any_technique: number;
  };
  aggregate: {
    regex_literals: number;
    new_regexp_calls: number;
    string_arrays_over_5: number;
    uses_taint_ast: number;
    uses_capability_graph: number;
    uses_module_graph: number;
    uses_entropy: number;
    uses_similarity: number;
    uses_evidence_chain_builder: number;
  };
  top_regex_offenders: Array<{ file: string; regex_literals: number; new_regexp_calls: number }>;
}

export interface CensusOutput {
  summary: CensusSummary;
  rows: CensusRow[];
}

// ─── YAML Side: read every rule file ───────────────────────────────────────

interface RuleYaml {
  id?: string;
  name?: string;
  category?: string;
  severity?: string;
  enabled?: boolean;
  detect?: { type?: string };
  engine_v2?: boolean;
}

function loadYamlRules(): Map<string, RuleYaml> {
  const out = new Map<string, RuleYaml>();
  if (!existsSync(RULES_YAML_DIR)) {
    return out;
  }
  for (const file of readdirSync(RULES_YAML_DIR)) {
    if (!file.endsWith(".yaml") && !file.endsWith(".yml")) continue;
    if (file === "framework-registry.yaml") continue;
    const full = join(RULES_YAML_DIR, file);
    try {
      const parsed = parseYaml(readFileSync(full, "utf8")) as RuleYaml;
      if (parsed?.id) out.set(parsed.id, parsed);
    } catch {
      // Ignore malformed files — a separate validator owns structural checks
    }
  }
  return out;
}

// ─── Detector Side: AST-scan each implementation file ─────────────────────

interface DetectorScan {
  file: string;           // absolute path
  relative: string;       // repo-relative path
  registered_v1: Set<string>;
  registered_v2: Set<string>;
  observations: TechniqueObservations;
}

/**
 * Extract the string id referenced by `registerTypedRule(new XxxRule())` or
 * `registerTypedRule(makeRule("ID", ...))`. We resolve class-based calls by
 * scanning every class declaration in the file and reading its readonly
 * `id` property initializer. If a class references `id: "X"` more than once
 * we accept the first.
 */
function collectClassIds(sf: ts.SourceFile): Map<string, string> {
  // First pass: resolve top-level `const FOO = "X"` declarations so we can
  // dereference `readonly id = FOO;` style property initializers.
  const constStrings = new Map<string, string>();
  for (const stmt of sf.statements) {
    if (!ts.isVariableStatement(stmt)) continue;
    for (const decl of stmt.declarationList.declarations) {
      if (
        ts.isIdentifier(decl.name) &&
        decl.initializer &&
        ts.isStringLiteral(decl.initializer)
      ) {
        constStrings.set(decl.name.text, decl.initializer.text);
      }
    }
  }

  const out = new Map<string, string>();
  function visit(node: ts.Node): void {
    if (ts.isClassDeclaration(node) && node.name) {
      const className = node.name.text;
      for (const member of node.members) {
        if (
          !ts.isPropertyDeclaration(member) ||
          !ts.isIdentifier(member.name) ||
          member.name.text !== "id" ||
          !member.initializer
        ) {
          continue;
        }
        let value: string | null = null;
        if (ts.isStringLiteral(member.initializer)) {
          value = member.initializer.text;
        } else if (ts.isIdentifier(member.initializer)) {
          value = constStrings.get(member.initializer.text) ?? null;
        }
        if (value && RULE_ID_PATTERN.test(value)) {
          out.set(className, value);
          break;
        }
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);
  return out;
}

const RULE_ID_PATTERN = /^[A-Q]\d{1,2}$/;

function isRegisterCall(node: ts.CallExpression, name: "registerTypedRule" | "registerTypedRuleV2"): boolean {
  return ts.isIdentifier(node.expression) && node.expression.text === name;
}

function extractRegisteredIds(
  sf: ts.SourceFile,
  classIds: Map<string, string>,
): { v1: Set<string>; v2: Set<string> } {
  const v1 = new Set<string>();
  const v2 = new Set<string>();

  function resolveArg(arg: ts.Expression): string | null {
    // registerTypedRule(new FooRule())
    if (ts.isNewExpression(arg) && arg.expression && ts.isIdentifier(arg.expression)) {
      return classIds.get(arg.expression.text) ?? null;
    }
    // registerTypedRule(makeRule("A1", ...)) or registerTypedRule(buildRule("...", ...))
    if (ts.isCallExpression(arg) && arg.arguments.length > 0) {
      const first = arg.arguments[0];
      if (ts.isStringLiteral(first) && RULE_ID_PATTERN.test(first.text)) {
        return first.text;
      }
    }
    // registerTypedRule({ id: "A1", ... }) — inline object literal
    if (ts.isObjectLiteralExpression(arg)) {
      for (const prop of arg.properties) {
        if (
          ts.isPropertyAssignment(prop) &&
          ts.isIdentifier(prop.name) &&
          prop.name.text === "id" &&
          prop.initializer &&
          ts.isStringLiteral(prop.initializer) &&
          RULE_ID_PATTERN.test(prop.initializer.text)
        ) {
          return prop.initializer.text;
        }
      }
    }
    // registerTypedRule(fooRuleInstance) — cannot resolve statically, skip
    return null;
  }

  let registersV1 = false;
  let registersV2 = false;

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      if (isRegisterCall(node, "registerTypedRule") && node.arguments.length > 0) {
        registersV1 = true;
        const id = resolveArg(node.arguments[0]);
        if (id) v1.add(id);
      } else if (isRegisterCall(node, "registerTypedRuleV2") && node.arguments.length > 0) {
        registersV2 = true;
        const id = resolveArg(node.arguments[0]);
        if (id) v2.add(id);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(sf);

  // Fallback pass for config-array patterns such as:
  //   const RULES: RuleCfg[] = [{ id: "K1", ... }, { id: "K4", ... }, ...];
  //   for (const cfg of RULES) registerTypedRule(buildRule(cfg));
  // If the file contains at least one registerTypedRule* call AND configs
  // with `id: "<valid>"` properties that weren't yet harvested, credit the
  // file for those ids. Which bucket (v1/v2) mirrors the file's calls; if
  // both, prefer v2 since buildRule-style detectors usually target v2.
  if (registersV1 || registersV2) {
    const harvested = new Set<string>();
    function harvest(node: ts.Node): void {
      if (ts.isObjectLiteralExpression(node)) {
        for (const prop of node.properties) {
          if (
            ts.isPropertyAssignment(prop) &&
            ts.isIdentifier(prop.name) &&
            prop.name.text === "id" &&
            prop.initializer &&
            ts.isStringLiteral(prop.initializer) &&
            RULE_ID_PATTERN.test(prop.initializer.text)
          ) {
            harvested.add(prop.initializer.text);
          }
        }
      }
      ts.forEachChild(node, harvest);
    }
    harvest(sf);
    const target = registersV2 && !registersV1 ? v2 : v1;
    for (const id of harvested) {
      if (!v1.has(id) && !v2.has(id)) target.add(id);
    }
  }

  return { v1, v2 };
}

/**
 * Count AST-level static-pattern indicators and toolkit imports.
 * This is the "technique_observed" evidence that the census reports.
 */
function observeTechniques(sf: ts.SourceFile, text: string): TechniqueObservations {
  const obs: TechniqueObservations = {
    regex_literals: 0,
    new_regexp_calls: 0,
    string_arrays_over_5: 0,
    ts_compiler_api_import: false,
    tree_sitter_import: false,
    uses_taint_ast: false,
    uses_capability_graph: false,
    uses_module_graph: false,
    uses_entropy: false,
    uses_similarity: false,
    uses_schema_inference: false,
    uses_evidence_chain_builder: false,
  };

  function visit(node: ts.Node): void {
    // Regex literal
    if (ts.isRegularExpressionLiteral(node)) obs.regex_literals++;

    // new RegExp(...) OR RegExp(...)
    if (
      (ts.isNewExpression(node) || ts.isCallExpression(node)) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "RegExp"
    ) {
      obs.new_regexp_calls++;
    }

    // String-literal arrays > 5 entries
    if (ts.isArrayLiteralExpression(node) && node.elements.length > 5) {
      const allStrings = node.elements.every(
        (e) => ts.isStringLiteral(e) || ts.isNoSubstitutionTemplateLiteral(e),
      );
      if (allStrings) obs.string_arrays_over_5++;
    }

    // Imports — record which analyzer toolkits are used by path substring.
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const spec = node.moduleSpecifier.text;
      if (spec === "typescript") obs.ts_compiler_api_import = true;
      if (spec.startsWith("tree-sitter")) obs.tree_sitter_import = true;
      if (spec.includes("taint-ast")) obs.uses_taint_ast = true;
      if (spec.includes("capability-graph")) obs.uses_capability_graph = true;
      if (spec.includes("module-graph")) obs.uses_module_graph = true;
      if (spec.includes("entropy")) obs.uses_entropy = true;
      if (spec.includes("similarity")) obs.uses_similarity = true;
      if (spec.includes("schema-inference")) obs.uses_schema_inference = true;
      if (spec.endsWith("/evidence.js") || spec.endsWith("/evidence")) {
        // evidence chain usage detected separately by identifier scan below
      }
    }

    ts.forEachChild(node, visit);
  }
  visit(sf);

  // Cheap identifier probe for EvidenceChainBuilder (string contains OK — this
  // is a census metric, not a security guard)
  obs.uses_evidence_chain_builder = /\bEvidenceChainBuilder\b/.test(text);

  return obs;
}

function scanDetectorFile(full: string): DetectorScan {
  const text = readFileSync(full, "utf8");
  const sf = ts.createSourceFile(full, text, ts.ScriptTarget.ES2022, true);
  const classIds = collectClassIds(sf);
  const { v1, v2 } = extractRegisteredIds(sf, classIds);
  const observations = observeTechniques(sf, text);
  return {
    file: full,
    relative: relative(REPO_ROOT, full),
    registered_v1: v1,
    registered_v2: v2,
    observations,
  };
}

function scanAllDetectors(): DetectorScan[] {
  if (!existsSync(DETECTOR_DIR)) return [];
  const out: DetectorScan[] = [];
  for (const name of readdirSync(DETECTOR_DIR)) {
    if (!name.endsWith(".ts") || name.endsWith(".test.ts")) continue;
    out.push(scanDetectorFile(join(DETECTOR_DIR, name)));
  }
  return out;
}

// ─── Join + Output ──────────────────────────────────────────────────────────

function join_(
  yamlRules: Map<string, RuleYaml>,
  detectors: DetectorScan[],
): CensusOutput {
  // Build rule_id → detector map
  const idToDetector = new Map<string, { v1: boolean; v2: boolean; scan: DetectorScan }>();
  for (const scan of detectors) {
    for (const id of scan.registered_v1) {
      const prev = idToDetector.get(id);
      idToDetector.set(id, { v1: true, v2: prev?.v2 ?? false, scan });
    }
    for (const id of scan.registered_v2) {
      const prev = idToDetector.get(id);
      idToDetector.set(id, { v1: prev?.v1 ?? false, v2: true, scan });
    }
  }

  const allIds = new Set<string>([...yamlRules.keys(), ...idToDetector.keys()]);
  const rows: CensusRow[] = [];

  for (const id of allIds) {
    const yaml = yamlRules.get(id);
    const detector = idToDetector.get(id);
    const notes: string[] = [];

    if (yaml && yaml.enabled !== false && !detector) {
      notes.push("enabled in YAML but no TypedRule registration found");
    }
    if (!yaml && detector) {
      notes.push("registered in code but no YAML metadata file");
    }
    if (yaml?.enabled === false && detector) {
      notes.push("disabled in YAML but still registered");
    }

    rows.push({
      rule_id: id,
      name: yaml?.name ?? null,
      category: yaml?.category ?? null,
      severity: yaml?.severity ?? null,
      enabled: yaml?.enabled !== false,
      yaml_detect_type: yaml?.detect?.type ?? null,
      yaml_engine_v2: yaml?.engine_v2 === true,
      registered_v1: detector?.v1 ?? false,
      registered_v2: detector?.v2 ?? false,
      detector_file: detector?.scan.relative ?? null,
      technique_observed: detector?.scan.observations ?? null,
      notes,
    });
  }

  rows.sort((a, b) => a.rule_id.localeCompare(b.rule_id, "en", { numeric: true }));

  // Summary
  const enabledYaml = [...yamlRules.values()].filter((r) => r.enabled !== false).length;
  const registered = idToDetector.size;
  const registeredV1 = rows.filter((r) => r.registered_v1).length;
  const registeredV2 = rows.filter((r) => r.registered_v2).length;
  const unregisteredEnabled = rows.filter(
    (r) => r.enabled && !r.registered_v1 && !r.registered_v2,
  ).length;

  const filesWithRegex = detectors.filter(
    (d) => d.observations.regex_literals + d.observations.new_regexp_calls > 0,
  ).length;
  const filesWithTechnique = detectors.filter(
    (d) =>
      d.observations.uses_taint_ast ||
      d.observations.uses_capability_graph ||
      d.observations.uses_module_graph ||
      d.observations.uses_entropy ||
      d.observations.uses_similarity ||
      d.observations.uses_schema_inference,
  ).length;

  // Aggregate is per DETECTOR FILE (not per rule) to avoid double-counting when
  // one file registers many rules. "Rules using X" counts are still per-rule.
  const agg = {
    regex_literals: sum(detectors, (d) => d.observations.regex_literals),
    new_regexp_calls: sum(detectors, (d) => d.observations.new_regexp_calls),
    string_arrays_over_5: sum(detectors, (d) => d.observations.string_arrays_over_5),
    uses_taint_ast: rows.filter((r) => r.technique_observed?.uses_taint_ast).length,
    uses_capability_graph: rows.filter((r) => r.technique_observed?.uses_capability_graph).length,
    uses_module_graph: rows.filter((r) => r.technique_observed?.uses_module_graph).length,
    uses_entropy: rows.filter((r) => r.technique_observed?.uses_entropy).length,
    uses_similarity: rows.filter((r) => r.technique_observed?.uses_similarity).length,
    uses_evidence_chain_builder: rows.filter((r) => r.technique_observed?.uses_evidence_chain_builder).length,
  };

  const topRegex = [...detectors]
    .sort(
      (a, b) =>
        b.observations.regex_literals +
        b.observations.new_regexp_calls -
        (a.observations.regex_literals + a.observations.new_regexp_calls),
    )
    .slice(0, 10)
    .map((d) => ({
      file: d.relative,
      regex_literals: d.observations.regex_literals,
      new_regexp_calls: d.observations.new_regexp_calls,
    }));

  const summary: CensusSummary = {
    generated_at: new Date().toISOString(),
    total_yaml_rules: yamlRules.size,
    enabled_yaml_rules: enabledYaml,
    registered_rules: registered,
    registered_v1: registeredV1,
    registered_v2: registeredV2,
    unregistered_enabled: unregisteredEnabled,
    detectors: {
      total_files: detectors.length,
      files_with_any_regex: filesWithRegex,
      files_with_any_technique: filesWithTechnique,
    },
    aggregate: agg,
    top_regex_offenders: topRegex,
  };

  return { summary, rows };
}

function sum<T>(xs: T[], pick: (x: T) => number): number {
  let total = 0;
  for (const x of xs) total += pick(x);
  return total;
}

function renderMarkdown(out: CensusOutput): string {
  const { summary, rows } = out;
  const lines: string[] = [];
  lines.push("# Rule Census");
  lines.push("");
  lines.push(`_Generated: ${summary.generated_at}_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("|---|---|");
  lines.push(`| YAML rules (total) | ${summary.total_yaml_rules} |`);
  lines.push(`| YAML rules (enabled) | ${summary.enabled_yaml_rules} |`);
  lines.push(`| Registered rules (unique ids) | ${summary.registered_rules} |`);
  lines.push(`| Registered v1 | ${summary.registered_v1} |`);
  lines.push(`| Registered v2 | ${summary.registered_v2} |`);
  lines.push(`| Enabled but unregistered | ${summary.unregistered_enabled} |`);
  lines.push(`| Detector files | ${summary.detectors.total_files} |`);
  lines.push(`| Files with any regex | ${summary.detectors.files_with_any_regex} |`);
  lines.push(`| Files with any technique import | ${summary.detectors.files_with_any_technique} |`);
  lines.push("");
  lines.push("## Aggregate Technique Observations");
  lines.push("");
  lines.push("| Signal | Count |");
  lines.push("|---|---|");
  lines.push(`| Regex literals | ${summary.aggregate.regex_literals} |`);
  lines.push(`| new RegExp(...) calls | ${summary.aggregate.new_regexp_calls} |`);
  lines.push(`| String-literal arrays > 5 | ${summary.aggregate.string_arrays_over_5} |`);
  lines.push(`| Rules using taint-ast | ${summary.aggregate.uses_taint_ast} |`);
  lines.push(`| Rules using capability-graph | ${summary.aggregate.uses_capability_graph} |`);
  lines.push(`| Rules using module-graph | ${summary.aggregate.uses_module_graph} |`);
  lines.push(`| Rules using entropy | ${summary.aggregate.uses_entropy} |`);
  lines.push(`| Rules using similarity | ${summary.aggregate.uses_similarity} |`);
  lines.push(`| Rules using EvidenceChainBuilder | ${summary.aggregate.uses_evidence_chain_builder} |`);
  lines.push("");
  lines.push("## Top Regex Offenders (detector files)");
  lines.push("");
  lines.push("| File | Regex literals | new RegExp calls |");
  lines.push("|---|---:|---:|");
  for (const o of summary.top_regex_offenders) {
    lines.push(`| \`${o.file}\` | ${o.regex_literals} | ${o.new_regexp_calls} |`);
  }
  lines.push("");
  lines.push("## Per-Rule Detail");
  lines.push("");
  lines.push("Columns: enabled (E), v1 registered (1), v2 registered (2), regex count (R), analyzer toolkit (T).");
  lines.push("T = first-letter tags: a=ast-taint, c=capability-graph, m=module-graph, e=entropy, s=similarity, i=schema-inference, v=EvidenceChainBuilder.");
  lines.push("");
  lines.push("> _Registration harvest caveat: for detectors of the form_ `for (cfg of RULES) registerTypedRule(buildRule(cfg))`, _the census credits every config object with an `id:` property, even if the runtime loop filters some out. Regex counts and toolkit imports are exact._");
  lines.push("");
  lines.push("| ID | Name | Cat | Sev | E | 1 | 2 | R | T | Detector |");
  lines.push("|---|---|---|---|:-:|:-:|:-:|---:|---|---|");
  for (const r of rows) {
    const tech = r.technique_observed;
    const regexCount = (tech?.regex_literals ?? 0) + (tech?.new_regexp_calls ?? 0);
    const tags = tech
      ? [
          tech.uses_taint_ast ? "a" : "",
          tech.uses_capability_graph ? "c" : "",
          tech.uses_module_graph ? "m" : "",
          tech.uses_entropy ? "e" : "",
          tech.uses_similarity ? "s" : "",
          tech.uses_schema_inference ? "i" : "",
          tech.uses_evidence_chain_builder ? "v" : "",
        ].join("")
      : "";
    lines.push(
      `| ${r.rule_id} | ${r.name ?? "—"} | ${r.category ?? "—"} | ${r.severity ?? "—"} | ${r.enabled ? "Y" : "N"} | ${r.registered_v1 ? "Y" : ""} | ${r.registered_v2 ? "Y" : ""} | ${regexCount} | ${tags || "—"} | ${r.detector_file ? `\`${r.detector_file.replace("packages/analyzer/src/rules/implementations/", "")}\`` : "—"} |`,
    );
  }
  lines.push("");
  const flagged = rows.filter((r) => r.notes.length > 0);
  if (flagged.length > 0) {
    lines.push("## Notes");
    lines.push("");
    for (const r of flagged) {
      lines.push(`- **${r.rule_id}**: ${r.notes.join("; ")}`);
    }
    lines.push("");
  }
  return lines.join("\n");
}

// ─── Entry ──────────────────────────────────────────────────────────────────

function main(): void {
  const args = process.argv.slice(2);
  const jsonOnly = args.includes("--json-only");
  const dateIdx = args.indexOf("--date");
  const today = dateIdx >= 0 ? args[dateIdx + 1] : new Date().toISOString().slice(0, 10);

  const yamlRules = loadYamlRules();
  const detectors = scanAllDetectors();
  const out = join_(yamlRules, detectors);

  if (!existsSync(CENSUS_DIR)) mkdirSync(CENSUS_DIR, { recursive: true });
  writeFileSync(join(CENSUS_DIR, `${today}.json`), JSON.stringify(out, null, 2));
  if (!jsonOnly) {
    writeFileSync(join(CENSUS_DIR, "latest.md"), renderMarkdown(out));
  }

  // Console summary — keep it short and grep-friendly
  const s = out.summary;
  process.stdout.write(
    `rule-census: ${s.total_yaml_rules} yaml (${s.enabled_yaml_rules} enabled), ` +
      `${s.registered_rules} registered (${s.registered_v1}v1 / ${s.registered_v2}v2), ` +
      `${s.unregistered_enabled} unregistered. ` +
      `${s.aggregate.regex_literals} regex literals across ${s.detectors.total_files} detector files. ` +
      `Wrote docs/census/${today}.json` +
      (jsonOnly ? "" : " + latest.md") +
      "\n",
  );
}

main();
