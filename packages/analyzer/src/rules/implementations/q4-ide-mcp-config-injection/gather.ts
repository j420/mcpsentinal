/**
 * Q4 evidence gathering — structural AST walk.
 *
 * Emits three primitive kinds:
 *   1. ide-config-write      — fs write targeting an IDE MCP config file
 *   2. auto-approve-write    — object literal assigns an auto-approve key
 *                              to `true`
 *   3. case-variant-filename — write path uses a case-variant spelling of
 *                              mcp.json / settings.json (CVE-2025-59944)
 *
 * Zero regex. All vocabulary lives in `./data/ide-targets.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  AUTO_APPROVE_KEYS,
  CANONICAL_MCP_FILENAMES,
  IDE_CONFIG_TARGETS,
  type IdeTarget,
} from "./data/ide-targets.js";

const IDE_TARGET_ENTRIES: ReadonlyArray<readonly [string, IdeTarget]> =
  Object.entries(IDE_CONFIG_TARGETS);

const AUTO_APPROVE_LOOKUP: ReadonlySet<string> = new Set(
  Object.keys(AUTO_APPROVE_KEYS).map((k) => k.toLowerCase()),
);

const CANONICAL_FILENAMES: ReadonlySet<string> = new Set(
  Object.keys(CANONICAL_MCP_FILENAMES),
);

// ─── Public types ──────────────────────────────────────────────────────────

export type Q4PrimitiveKind = "ide-config-write" | "auto-approve-write" | "case-variant-filename";

export interface Q4Fact {
  kind: Q4PrimitiveKind;
  /** Source Location for the offending expression / property. */
  location: Location;
  /** Short text observation. */
  observed: string;
  /** IDE this concerns. Null if the fact is not IDE-specific (e.g. auto-approve with no target file). */
  target: IdeTarget | null;
  /** Structured Location for the victim IDE config (if known). */
  targetLocation: Location | null;
  /** Raw matched path suffix (for ide-config-write / case-variant-filename). */
  matchedSuffix: string | null;
  /** Observed path text, preserving original casing (case-variant evidence). */
  observedPath: string | null;
}

export interface Q4GatherResult {
  file: string;
  isTestFile: boolean;
  facts: Q4Fact[];
}

const SYNTHETIC_FILE = "<source>";

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherQ4(context: AnalysisContext): Q4GatherResult {
  const src = context.source_code;
  if (!src) return { file: SYNTHETIC_FILE, isTestFile: false, facts: [] };

  const file = firstFile(context.source_files) ?? SYNTHETIC_FILE;
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileShape(sf);

  const facts: Q4Fact[] = [];

  const visit = (node: ts.Node): void => {
    // Primitive 1 + 3: fs writes whose path is an IDE config target (or
    // a case-variant of one).
    if (ts.isCallExpression(node) && isWriteCall(node)) {
      collectWriteFacts(node, sf, file, facts);
    }
    // Primitive 2: object literals assigning auto-approve key = true.
    if (ts.isObjectLiteralExpression(node)) {
      collectAutoApproveFacts(node, sf, file, facts);
    }
    // Primitive 2 (secondary): assignment expressions like
    // `config.enableAllProjectMcpServers = true`.
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      collectAssignmentAutoApprove(node, sf, file, facts);
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

// ─── Primitive 1 + 3: write calls ────────────────────────────────────────

function isWriteCall(node: ts.CallExpression): boolean {
  const callee = node.expression;
  let name: string | null = null;
  if (ts.isIdentifier(callee)) name = callee.text;
  else if (ts.isPropertyAccessExpression(callee)) name = callee.name.text;
  if (name === null) return false;
  return name === "writeFileSync" || name === "writeFile" ||
         name === "appendFile" || name === "appendFileSync" ||
         name === "outputFile" || name === "outputFileSync" ||
         name === "writeJson" || name === "writeJSON";
}

function firstArgText(node: ts.CallExpression, sf: ts.SourceFile): { text: string; loc: Location; file: string } | null {
  if (node.arguments.length === 0) return null;
  const arg = node.arguments[0];
  const loc = locOf(sf, sf.fileName, arg);
  const file = sf.fileName;
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
    return { text: arg.text, loc, file };
  }
  if (ts.isTemplateExpression(arg)) {
    const parts: string[] = [arg.head.text];
    for (const span of arg.templateSpans) parts.push(span.literal.text);
    return { text: parts.join(""), loc, file };
  }
  return null;
}

function collectWriteFacts(
  node: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  out: Q4Fact[],
): void {
  const info = firstArgText(node, sf);
  if (info === null) return;
  const orig = info.text;
  const norm = orig.toLowerCase().split("\\").join("/");

  // Case-variant primitive: check BEFORE the ide-config-write check so
  // a mixed-case filename inside a non-IDE directory still surfaces.
  for (const canonical of CANONICAL_FILENAMES) {
    const idx = norm.indexOf(canonical);
    if (idx < 0) continue;
    // Extract the same-length substring from the original text (case-preserving).
    const originalSegment = orig.slice(idx, idx + canonical.length);
    if (originalSegment !== canonical) {
      // Case-variant hit.
      out.push({
        kind: "case-variant-filename",
        location: info.loc,
        observed: `write path "${orig}" uses case variant "${originalSegment}" of "${canonical}"`,
        target: null,
        targetLocation: { kind: "config", file: orig, json_pointer: "/" },
        matchedSuffix: canonical,
        observedPath: orig,
      });
      // Continue checking — the path may ALSO match an IDE target below.
      break;
    }
  }

  // IDE-config-write primitive: path suffix match against the IDE registry.
  for (const [suffix, target] of IDE_TARGET_ENTRIES) {
    const idx = norm.indexOf(suffix);
    if (idx < 0) continue;
    // Boundary check — separator or quote / ~ before the match.
    const allowBoundary = idx === 0 ||
      norm[idx - 1] === "/" || norm[idx - 1] === "~" ||
      norm[idx - 1] === "\"" || norm[idx - 1] === "'";
    if (!allowBoundary) continue;
    out.push({
      kind: "ide-config-write",
      location: info.loc,
      observed: `write targeting ${target.label}: "${orig.slice(0, 120)}"`,
      target,
      targetLocation: { kind: "config", file: orig, json_pointer: "/" },
      matchedSuffix: suffix,
      observedPath: orig,
    });
    break;
  }
  void file; // retain param for API symmetry
}

// ─── Primitive 2: auto-approve key writes ─────────────────────────────────

function collectAutoApproveFacts(
  lit: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
  out: Q4Fact[],
): void {
  for (const prop of lit.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === null) continue;
    if (!AUTO_APPROVE_LOOKUP.has(key.toLowerCase())) continue;
    if (prop.initializer.kind !== ts.SyntaxKind.TrueKeyword) continue;
    out.push({
      kind: "auto-approve-write",
      location: locOf(sf, file, prop),
      observed: `${key}: true`,
      target: null,
      targetLocation: null,
      matchedSuffix: null,
      observedPath: null,
    });
  }
}

function collectAssignmentAutoApprove(
  node: ts.BinaryExpression,
  sf: ts.SourceFile,
  file: string,
  out: Q4Fact[],
): void {
  if (!ts.isPropertyAccessExpression(node.left)) return;
  if (node.right.kind !== ts.SyntaxKind.TrueKeyword) return;
  const name = node.left.name.text;
  if (!AUTO_APPROVE_LOOKUP.has(name.toLowerCase())) return;
  out.push({
    kind: "auto-approve-write",
    location: locOf(sf, file, node),
    observed: `${node.left.getText(sf)} = true`,
    target: null,
    targetLocation: null,
    matchedSuffix: null,
    observedPath: null,
  });
}
