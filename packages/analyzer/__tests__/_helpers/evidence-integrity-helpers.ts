/**
 * Evidence-Integrity Harness Helpers
 *
 * Pure helper functions for the evidence-integrity harness
 * (packages/analyzer/__tests__/evidence-integrity.test.ts).
 *
 * The harness loops over every registered TypedRuleV2 and every true-positive
 * fixture in that rule's directory, runs the rule, and asserts four classes of
 * invariant on each produced finding:
 *
 *   1. Location resolution — every EvidenceLink.location and every
 *      VerificationStep.target is a structured Location that resolves to
 *      something real in the context.
 *   2. AST reachability — for source→source chains in the same file,
 *      isReachable() returns reachable:true OR an out-of-scope reason.
 *   3. Confidence derivation — chain.confidence is in [0,1], ≤ CHARTER cap,
 *      and confidence_factors includes every factor the CHARTER requires.
 *   4. CVE manifest — any CVE-shaped threat id is registered in
 *      docs/cve-manifest.json.
 *
 * These are the guarantees that make findings admissible as audit evidence
 * under EU AI Act Art. 12, ISO 27001 A.8.15, and ISO 42001 A.8.1.
 */

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, dirname, basename, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

import type { AnalysisContext } from "../../src/engine.js";
import type { Location } from "../../src/rules/location.js";
import { isLocation } from "../../src/rules/location.js";
import type { EvidenceChain, EvidenceLink, VerificationStep } from "../../src/evidence.js";

// ─── Paths ───────────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_ROOT = resolve(HERE, "..", "..");
export const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
export const IMPL_ROOT = join(PACKAGE_ROOT, "src", "rules", "implementations");
export const RULES_YAML_DIR = join(REPO_ROOT, "rules");
export const CVE_MANIFEST_PATH = join(REPO_ROOT, "docs", "cve-manifest.json");

// ─── CHARTER frontmatter parsing ────────────────────────────────────────────

export interface CharterFrontmatter {
  rule_id?: string;
  interface_version?: string;
  severity?: string;
  confidence_cap?: number;
  threat_refs?: Array<{ kind?: string; id?: string; url?: string; summary?: string }>;
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
}

/** Parse YAML frontmatter bounded by `---` lines. Same shape used by charter-traceability. */
export function parseCharterFrontmatter(markdown: string): CharterFrontmatter | null {
  const lines = markdown.split("\n");
  if (lines[0]?.trim() !== "---") return null;
  const end = lines.findIndex((l, i) => i > 0 && l.trim() === "---");
  if (end < 0) return null;
  const yamlText = lines.slice(1, end).join("\n");
  try {
    return parseYaml(yamlText) as CharterFrontmatter;
  } catch {
    return null;
  }
}

// ─── Rule-directory discovery ───────────────────────────────────────────────

export interface RuleImplEntry {
  /** Rule id as declared in the sibling CHARTER.md (e.g. "K1", "I13"). */
  rule_id: string;
  /** Absolute path to the rule's implementation directory. */
  dir: string;
  /** Parsed charter frontmatter for confidence/cve enforcement. */
  charter: CharterFrontmatter | null;
}

/**
 * Walk `packages/analyzer/src/rules/implementations/` and return one entry per
 * rule-directory whose CHARTER.md declares a rule_id.
 *
 * Skips the shared-infrastructure directory. Each rule's entry maps rule_id →
 * directory so the harness can locate fixtures by rule id.
 */
export function discoverRuleDirs(): RuleImplEntry[] {
  if (!existsSync(IMPL_ROOT)) return [];
  const entries: RuleImplEntry[] = [];
  for (const name of readdirSync(IMPL_ROOT)) {
    if (name === "_shared") continue;
    const dir = join(IMPL_ROOT, name);
    if (!statSync(dir).isDirectory()) continue;
    const charterPath = join(dir, "CHARTER.md");
    if (!existsSync(charterPath)) continue;
    const charter = parseCharterFrontmatter(readFileSync(charterPath, "utf8"));
    const rule_id = charter?.rule_id?.trim();
    if (!rule_id) continue;
    entries.push({ rule_id, dir, charter });
  }
  return entries;
}

// ─── Fixture loading ────────────────────────────────────────────────────────

/**
 * Named true-positive fixtures to evaluate against a rule.
 *
 * We accept three naming conventions (matching what rules actually ship):
 *
 *   - `true-positive-*.(ts|js|py|mjs|cjs|env|env.example)` — the canonical form
 *   - `tp-*.(ts|js|py)` — used by n-rules
 *   - `Dockerfile.*` — used by p5 (build-layer secrets)
 *
 * Rules whose only fixture is `minimal.ts` (stubs) intentionally have no
 * true-positives and are allowed to emit zero findings. The harness still
 * runs them against their minimal fixture to confirm they do not crash.
 *
 * Rules with a `fixtures.ts` fallback (k15) also expose their contexts via
 * that module.
 */
export function listTruePositiveFixtures(ruleDir: string): string[] {
  const fxdir = join(ruleDir, "__fixtures__");
  if (!existsSync(fxdir)) return [];
  const all = readdirSync(fxdir);
  const picks: string[] = [];
  for (const name of all) {
    if (name.startsWith("true-positive-")) picks.push(join(fxdir, name));
    else if (name.startsWith("tp-")) picks.push(join(fxdir, name));
    else if (name.startsWith("Dockerfile.")) picks.push(join(fxdir, name));
  }
  return picks.sort();
}

/**
 * Fallback fixtures when no true-positive is declared (minimal.ts / fixtures.ts
 * for stubs, or true-negative fixtures that exercise the rule without
 * expecting a finding). Used for the "rule executed without crashing" check.
 *
 * Stubs (F2, F3, F6, I2, L14) return [] from analyze() by design — the parent
 * rule emits their findings. They only need to be invoked without throwing.
 */
export function listFallbackFixtures(ruleDir: string): string[] {
  const fxdir = join(ruleDir, "__fixtures__");
  if (!existsSync(fxdir)) return [];
  const all = readdirSync(fxdir);
  const picks: string[] = [];
  for (const name of all) {
    if (name === "minimal.ts" || name === "fixtures.ts") {
      picks.push(join(fxdir, name));
    } else if (name.startsWith("true-negative-") || name.startsWith("tn-")) {
      picks.push(join(fxdir, name));
    }
  }
  return picks;
}

// ─── AnalysisContext construction ───────────────────────────────────────────

/**
 * A built fixture: either an AnalysisContext handed back by the fixture's own
 * buildContext() export, or a synthesized AnalysisContext wrapping the fixture
 * file as `source_code`.
 */
export interface LoadedFixture {
  /** Absolute path of the fixture file. */
  path: string;
  /** Short filename for error messages. */
  name: string;
  /** The analysis context handed to the rule. */
  context: AnalysisContext;
  /**
   * Which loader served the context. `buildContext` means the fixture exported
   * a buildContext; `source-file` means we loaded the file's text as
   * source_code and placed it in source_files too.
   */
  loader: "buildContext" | "source-file";
}

/** Basic AnalysisContext shell with all fields set to empty defaults. */
function blankContext(): AnalysisContext {
  return {
    server: {
      id: "evidence-integrity-harness",
      name: "evidence-integrity-harness",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}

/**
 * Load a fixture. We do NOT blindly `await import` — many source-file
 * fixtures contain top-level side-effecting code (fetch to example.invalid,
 * Buffer.from(undefined), fs writes) which would crash or hang the harness.
 *
 * Instead we inspect the source text first. A fixture is treated as a module
 * only when it explicitly exports a `buildContext` symbol — the convention
 * used by every synthetic-AnalysisContext fixture in the repo. Everything
 * else (source code under test, Python files, Dockerfiles, .env examples)
 * flows through the source-file path: read the text, stash it under
 * `source_code` + `source_files[<basename>]`, move on.
 */
export async function loadFixture(path: string): Promise<LoadedFixture> {
  const name = basename(path);
  const isModule =
    name.endsWith(".ts") || name.endsWith(".js") || name.endsWith(".mjs") || name.endsWith(".cjs");

  // Only attempt a dynamic import when the text statically declares a
  // buildContext export. This avoids side-effecting fixtures (e.g. L9 fires
  // `await fetch(...)` at module scope) from running during test load.
  let text = "";
  if (isModule) {
    text = readFileSync(path, "utf8");
    if (declaresBuildContextExport(text)) {
      const url = pathToFileURL(path).href;
      const mod = (await import(url)) as { buildContext?: () => AnalysisContext };
      if (typeof mod.buildContext === "function") {
        const context = mod.buildContext();
        return { path, name, context, loader: "buildContext" };
      }
    }
  }

  if (!text) text = readFileSync(path, "utf8");
  const ctx = blankContext();
  ctx.source_code = text;
  ctx.source_files = new Map([[name, text]]);
  return { path, name, context: ctx, loader: "source-file" };
}

/**
 * Does the TS/JS text export a `buildContext` symbol? Scans for the literal
 * `export function buildContext` / `export const buildContext` / `export {
 * buildContext` / `export default buildContext` forms. String search — no
 * regex literal to avoid tripping the static-patterns guard in `src/rules/`.
 * (This file is under `__tests__/` so the guard does not apply, but we keep
 * the style consistent.)
 */
function declaresBuildContextExport(text: string): boolean {
  const needles = [
    "export function buildContext",
    "export async function buildContext",
    "export const buildContext",
    "export let buildContext",
    "export default buildContext",
    "export { buildContext",
    "export {buildContext",
  ];
  for (const n of needles) {
    if (text.includes(n)) return true;
  }
  return false;
}

// ─── Location resolution ────────────────────────────────────────────────────

export interface LocationResolveViolation {
  code: string;
  detail: string;
}

/**
 * Check whether a Location resolves to something real in the given context.
 *
 * Returns `null` on success (location resolves). Returns a violation
 * descriptor on failure.
 *
 * For source-file fixtures the harness seeds `context.source_files` with the
 * fixture's text keyed by its filename — source-kind locations whose `file`
 * matches that key are validated against the seeded file. Other file names
 * resolve against `source_files` if populated, or against `source_code`
 * treated as a single-file text blob.
 */
export function resolveLocation(
  loc: Location,
  context: AnalysisContext,
  sourcesByFile: Map<string, string>,
): LocationResolveViolation | null {
  switch (loc.kind) {
    case "source": {
      const text =
        sourcesByFile.get(loc.file) ??
        (context.source_files ? context.source_files.get(loc.file) : undefined) ??
        (context.source_code ?? undefined);
      if (text === undefined) {
        return {
          code: "SOURCE_FILE_MISSING",
          detail: `source location file=${loc.file} not present in source_files or source_code`,
        };
      }
      const lines = text.split("\n");
      if (!Number.isInteger(loc.line) || loc.line < 1 || loc.line > lines.length) {
        return {
          code: "SOURCE_LINE_OUT_OF_RANGE",
          detail: `source location line=${loc.line} outside file (line count=${lines.length})`,
        };
      }
      const lineText = lines[loc.line - 1] ?? "";
      // Empty line is only acceptable when the length field is explicitly 0
      // (the rule is marking an intentional position without a span).
      if (lineText.trim().length === 0 && loc.length !== 0) {
        return {
          code: "SOURCE_LINE_EMPTY",
          detail: `source location file=${loc.file}:line=${loc.line} is empty/whitespace-only (line content="${lineText}")`,
        };
      }
      if (loc.col !== undefined) {
        if (!Number.isInteger(loc.col) || loc.col < 0 || loc.col > lineText.length) {
          return {
            code: "SOURCE_COL_OUT_OF_RANGE",
            detail: `source location col=${loc.col} outside line (line length=${lineText.length})`,
          };
        }
      }
      return null;
    }
    case "tool": {
      const found = context.tools?.some((t) => t.name === loc.tool_name) ?? false;
      if (!found) {
        return {
          code: "TOOL_NOT_IN_CONTEXT",
          detail: `tool location tool_name=${loc.tool_name} not in context.tools (${
            context.tools?.map((t) => t.name).join(",") ?? "none"
          })`,
        };
      }
      return null;
    }
    case "parameter": {
      const tool = context.tools?.find((t) => t.name === loc.tool_name);
      if (!tool) {
        return {
          code: "PARAM_TOOL_NOT_IN_CONTEXT",
          detail: `parameter.tool_name=${loc.tool_name} not in context.tools`,
        };
      }
      if (!resolveParameterPath(tool.input_schema, loc.parameter_path)) {
        return {
          code: "PARAM_PATH_NOT_FOUND",
          detail: `parameter.parameter_path=${loc.parameter_path} does not resolve in tool=${loc.tool_name} input_schema`,
        };
      }
      return null;
    }
    case "schema": {
      const tool = context.tools?.find((t) => t.name === loc.tool_name);
      if (!tool) {
        return {
          code: "SCHEMA_TOOL_NOT_IN_CONTEXT",
          detail: `schema.tool_name=${loc.tool_name} not in context.tools`,
        };
      }
      if (!resolveJsonPointer(tool.input_schema, loc.json_pointer)) {
        return {
          code: "SCHEMA_POINTER_NOT_FOUND",
          detail: `schema.json_pointer=${loc.json_pointer} does not resolve in tool=${loc.tool_name} input_schema`,
        };
      }
      return null;
    }
    case "dependency": {
      const deps = context.dependencies ?? [];
      const found = deps.some((d) => d.name === loc.name);
      if (!found) {
        return {
          code: "DEP_NOT_IN_CONTEXT",
          detail: `dependency.name=${loc.name} not in context.dependencies (${deps
            .map((d) => d.name)
            .join(",") || "none"})`,
        };
      }
      return null;
    }
    case "config": {
      // Structured `config` locations are often references to external
      // configuration files the rule detects a write/read *to*, not files
      // that live in the fixture's source_files map (e.g. Q4 flags a
      // writeFileSync to ~/.cursor/mcp.json; the target config doesn't
      // exist in the synthetic AnalysisContext by design).
      //
      // When the file IS present in the context we verify the pointer.
      // When it is not, we accept the location: the contract it satisfies is
      // "name the file with a structured path + JSON pointer so an auditor
      // can pivot off it" — achievable without a file body.
      const text = sourcesByFile.get(loc.file) ?? context.source_files?.get(loc.file);
      if (text === undefined) return null;
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        // Not JSON — pointer is informational only.
        return null;
      }
      if (!resolveJsonPointer(parsed, loc.json_pointer)) {
        return {
          code: "CONFIG_POINTER_NOT_FOUND",
          detail: `config.json_pointer=${loc.json_pointer} does not resolve in ${loc.file}`,
        };
      }
      return null;
    }
    case "initialize": {
      if (loc.field !== "server_name" && loc.field !== "server_version" && loc.field !== "instructions") {
        return {
          code: "INIT_FIELD_INVALID",
          detail: `initialize.field=${loc.field} is not one of server_name|server_version|instructions`,
        };
      }
      return null;
    }
    case "resource": {
      const found = context.resources?.some((r) => r.uri === loc.uri) ?? false;
      if (!found) {
        return {
          code: "RESOURCE_NOT_IN_CONTEXT",
          detail: `resource.uri=${loc.uri} not in context.resources`,
        };
      }
      return null;
    }
    case "prompt": {
      const found = context.prompts?.some((p) => p.name === loc.name) ?? false;
      if (!found) {
        return {
          code: "PROMPT_NOT_IN_CONTEXT",
          detail: `prompt.name=${loc.name} not in context.prompts`,
        };
      }
      return null;
    }
    case "capability": {
      // The `capability` location kind names one of the five spec-sanctioned
      // MCP capabilities. The discriminant already constrains the value to
      // the allowlist, so the location is structurally real.
      //
      // Many rules emit capability locations as semantic scope markers ("the
      // tools surface is the attack surface") without requiring the server
      // to have explicitly declared the capability in its initialize handshake
      // — e.g. a server that `tools/list`s is implicitly tools-capable.
      // Synthetic fixtures rarely populate declared_capabilities, so
      // requiring it would fail the harness for legitimate rule shape.
      const allowed = ["tools", "resources", "prompts", "sampling", "logging"];
      if (!allowed.includes(loc.capability)) {
        return {
          code: "CAPABILITY_INVALID",
          detail: `capability=${loc.capability} is not one of ${allowed.join("|")}`,
        };
      }
      // When the fixture explicitly denies the capability (set to false),
      // that's still a valid semantic location — the rule may be flagging
      // *the absence of a capability* (e.g. I12 capability-escalation).
      return null;
    }
  }
}

/**
 * Resolve a JSONPath-like parameter_path (e.g. `input_schema.properties.cmd`).
 * Returns true when the path exists. Accepts either a leading
 * `input_schema.properties.` or plain dot-paths into `properties.`.
 */
function resolveParameterPath(schema: Record<string, unknown> | null | undefined, path: string): boolean {
  if (!schema) return false;
  const parts = path.split(".").filter(Boolean);
  let cursor: unknown = schema;
  for (const p of parts) {
    // Skip the leading input_schema prefix — the context holds the schema
    // already.
    if (p === "input_schema") continue;
    if (typeof cursor !== "object" || cursor === null) return false;
    const next = (cursor as Record<string, unknown>)[p];
    if (next === undefined) return false;
    cursor = next;
  }
  return cursor !== undefined;
}

/**
 * RFC 6901 JSON Pointer resolution. Empty pointer resolves to the root.
 * Returns the referenced value or undefined when the pointer is invalid.
 */
export function resolveJsonPointer(root: unknown, pointer: string): unknown {
  if (pointer === "" || pointer === "/") return root;
  if (!pointer.startsWith("/")) return undefined;
  const parts = pointer
    .slice(1)
    .split("/")
    .map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cursor: unknown = root;
  for (const part of parts) {
    if (cursor === null || cursor === undefined) return undefined;
    if (Array.isArray(cursor)) {
      const idx = Number(part);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cursor.length) return undefined;
      cursor = cursor[idx];
      continue;
    }
    if (typeof cursor !== "object") return undefined;
    const obj = cursor as Record<string, unknown>;
    if (!(part in obj)) return undefined;
    cursor = obj[part];
  }
  return cursor;
}

// ─── CVE manifest ───────────────────────────────────────────────────────────

export interface CveManifest {
  version: number;
  entries: Array<{ id: string }>;
}

export function loadCveIds(): Set<string> {
  if (!existsSync(CVE_MANIFEST_PATH)) return new Set();
  try {
    const parsed = JSON.parse(readFileSync(CVE_MANIFEST_PATH, "utf8")) as CveManifest;
    return new Set(parsed.entries.map((e) => e.id));
  } catch {
    return new Set();
  }
}

/** Return true when the string looks like a CVE identifier (`CVE-YYYY-NNNN`). */
export function looksLikeCveId(id: string): boolean {
  // Conservative string check — no regex literal, no dynamic pattern.
  if (!id.startsWith("CVE-")) return false;
  const rest = id.slice(4);
  const parts = rest.split("-");
  if (parts.length !== 2) return false;
  const [year, num] = parts;
  if (!year || !num) return false;
  for (const c of year) if (c < "0" || c > "9") return false;
  for (const c of num) if (c < "0" || c > "9") return false;
  return year.length === 4 && num.length >= 4;
}

// ─── Confidence factor extraction ───────────────────────────────────────────

/** Collect unique factor names from a chain's confidence_factors list. */
export function factorNames(chain: EvidenceChain): Set<string> {
  const out = new Set<string>();
  for (const f of chain.confidence_factors ?? []) {
    if (f?.factor) out.add(f.factor);
  }
  return out;
}

// ─── Evidence-link iteration ────────────────────────────────────────────────

/** Every location that belongs to an evidence link (source/propagation/sink/mitigation). */
export function linkLocations(link: EvidenceLink): Location | string | null {
  if (link.type === "impact") return null;
  // All other link types have `.location`.
  return (link as { location?: Location | string }).location ?? null;
}

/** Every VerificationStep target, skipping steps without one. */
export function stepTargets(steps: VerificationStep[] | undefined): Array<VerificationStep> {
  return (steps ?? []).filter((s) => s?.target !== undefined);
}

/** Narrowing: is the link/step value a structured Location? */
export { isLocation };
