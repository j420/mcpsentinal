/**
 * L11 evidence gathering — structural AST walk of MCP config env blocks.
 *
 * Identifies object-literal subtrees that look like MCP config
 * (`mcpServers` key + server entries with `env` blocks) and inspects
 * each env key against the L11 dangerous-key registry. Each hit becomes
 * a structured fact the rule's index.ts converts into a v2 finding.
 *
 * Case handling: env-key matching is case-insensitive at the check step
 * (Windows env is case-insensitive), but the observed text records the
 * ORIGINAL spelling so the evidence chain is faithful to the source.
 *
 * Zero regex. Vocabularies in `./data/*.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { RISKY_ENV_KEYS, type EnvRiskClass, type EnvRiskEntry } from "./data/risky-env-keys.js";
import { SAFE_ENV_KEYS } from "./data/safe-env-keys.js";

// Build a case-insensitive lookup map so LD_Preload still matches
// LD_PRELOAD on Windows-style case-insensitive interpretation.
const CI_RISKY_LOOKUP: ReadonlyMap<string, readonly [string, EnvRiskEntry]> = new Map(
  Object.entries(RISKY_ENV_KEYS).map(([key, entry]) => [key.toLowerCase(), [key, entry] as const]),
);

const SAFE_LOOKUP: ReadonlySet<string> = new Set(
  Object.keys(SAFE_ENV_KEYS).map((k) => k.toLowerCase()),
);

// ─── Public types ──────────────────────────────────────────────────────────

export interface L11Fact {
  /** Outer MCP-config literal Location — for the source link. */
  literalLocation: Location;
  /** The env entry's own Location — for the sink link. */
  entryLocation: Location;
  /** Observed key text, exactly as written in source (case-preserved). */
  observedKey: string;
  /** Canonical key name as it appears in RISKY_ENV_KEYS. */
  canonicalKey: string;
  /** The assigned value text (template / literal / expression). */
  observedValue: string;
  /** Classification. */
  riskClass: EnvRiskClass;
  /** Short rationale from the registry. */
  rationale: string;
  /** True if `observedKey !== canonicalKey` — the case-mutated variant. */
  caseMutated: boolean;
  /** True if the env block ALSO contains safe keys an allowlist would pass. */
  coexistsWithSafeKeys: boolean;
}

export interface L11GatherResult {
  file: string;
  isTestFile: boolean;
  facts: L11Fact[];
}

const SYNTHETIC_FILE = "<source>";

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherL11(context: AnalysisContext): L11GatherResult {
  const src = context.source_code;
  if (!src) return { file: SYNTHETIC_FILE, isTestFile: false, facts: [] };

  const file = firstFile(context.source_files) ?? SYNTHETIC_FILE;
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileShape(sf);

  const facts: L11Fact[] = [];

  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node)) {
      collectFromConfigLiteral(node, sf, file, facts);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);

  return { file, isTestFile, facts };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function firstFile(source_files: AnalysisContext["source_files"]): string | null {
  if (!source_files || source_files.size === 0) return null;
  return Array.from(source_files.keys())[0];
}

function detectTestFileShape(sf: ts.SourceFile): boolean {
  const name = sf.fileName.toLowerCase();
  if (name.endsWith(".test.ts") || name.endsWith(".test.js")) return true;
  if (name.endsWith(".spec.ts") || name.endsWith(".spec.js")) return true;
  if (name.includes("__tests__")) return true;
  let hasTestImport = false;
  let hasTestCall = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const s = stmt.moduleSpecifier.text;
      if (s === "vitest" || s === "jest" || s === "mocha") hasTestImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee)) {
        if (callee.text === "describe" || callee.text === "it" || callee.text === "test") {
          hasTestCall = true;
        }
      }
    }
  }
  return hasTestImport && hasTestCall;
}

function locOf(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = node.getStart(sf);
  const { line, character } = sf.getLineAndCharacterOfPosition(start);
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function propertyKeyName(prop: ts.PropertyAssignment): string | null {
  if (ts.isIdentifier(prop.name)) return prop.name.text;
  if (ts.isStringLiteral(prop.name)) return prop.name.text;
  return null;
}

function hasConfigContextMarker(node: ts.ObjectLiteralExpression): boolean {
  for (const prop of node.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const name = propertyKeyName(prop);
    if (name === "mcpServers" || name === "mcp_servers" || name === "mcp_config") return true;
  }
  return false;
}

function collectFromConfigLiteral(
  lit: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
  out: L11Fact[],
): void {
  if (!hasConfigContextMarker(lit)) return;

  const literalLocation = locOf(sf, file, lit);

  for (const prop of lit.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === null) continue;
    if (key !== "mcpServers" && key !== "mcp_servers" && key !== "mcp_config") continue;
    // Each server entry — inspect its env block.
    if (!ts.isObjectLiteralExpression(prop.initializer)) continue;
    for (const serverProp of prop.initializer.properties) {
      if (!ts.isPropertyAssignment(serverProp)) continue;
      if (!ts.isObjectLiteralExpression(serverProp.initializer)) continue;
      inspectServerEntry(serverProp.initializer, sf, file, literalLocation, out);
    }
  }
}

function inspectServerEntry(
  entry: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
  literalLocation: Location,
  out: L11Fact[],
): void {
  for (const prop of entry.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key !== "env") continue;
    if (!ts.isObjectLiteralExpression(prop.initializer)) continue;
    inspectEnvBlock(prop.initializer, sf, file, literalLocation, out);
  }
}

function inspectEnvBlock(
  block: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
  literalLocation: Location,
  out: L11Fact[],
): void {
  const entries: Array<{
    observedKey: string;
    lowerKey: string;
    prop: ts.PropertyAssignment;
  }> = [];
  for (const envProp of block.properties) {
    if (!ts.isPropertyAssignment(envProp)) continue;
    const key = propertyKeyName(envProp);
    if (key === null) continue;
    entries.push({ observedKey: key, lowerKey: key.toLowerCase(), prop: envProp });
  }

  // Which entries have safe-listed keys? Use the case-insensitive safe set.
  const hasSafeKeys = entries.some((e) => SAFE_LOOKUP.has(e.lowerKey));

  for (const e of entries) {
    const hit = CI_RISKY_LOOKUP.get(e.lowerKey);
    if (!hit) continue;
    const [canonical, info] = hit;
    const observedValue = literalOrTemplateText(e.prop.initializer);
    out.push({
      literalLocation,
      entryLocation: locOf(sf, file, e.prop),
      observedKey: e.observedKey,
      canonicalKey: canonical,
      observedValue,
      riskClass: info.riskClass,
      rationale: info.rationale,
      caseMutated: e.observedKey !== canonical,
      coexistsWithSafeKeys: hasSafeKeys,
    });
  }
}

function literalOrTemplateText(node: ts.Expression): string {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) {
    const parts: string[] = [node.head.text];
    for (const span of node.templateSpans) {
      parts.push("${...}");
      parts.push(span.literal.text);
    }
    return parts.join("");
  }
  return node.getText();
}
