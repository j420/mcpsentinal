/**
 * L6 — Config Directory Symlink Attack: deterministic AST walker.
 *
 * Emits two fact kinds:
 *   - symlink-creation  : fs.symlink(target, linkpath) where target
 *                         hits the sensitive-paths vocabulary.
 *   - unguarded-read    : fs.readFile / fs.open / fs.createReadStream
 *                         whose enclosing function contains NO
 *                         realpath / lstat / O_NOFOLLOW guard.
 *
 * Every finding carries a `source`-kind Location (file:line:col) so the
 * auditor can jump straight to the call.
 *
 * No regex literals. All vocabularies live under `./data/`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SENSITIVE_TARGET_PATHS,
  SYMLINK_CREATE_CALLEES,
  READ_CALLEES,
  SYMLINK_GUARD_CALLEES,
  NOFOLLOW_FLAG_TOKENS,
  ATTACKER_REACHABLE_CONFIG_DIRS,
} from "./data/symlink-vocabulary.js";

export type L6FactKind = "symlink-creation" | "unguarded-read";

export interface L6Fact {
  kind: L6FactKind;
  /** source-kind Location for the offending call. */
  location: Location;
  /** Verbatim call text (truncated). */
  observed: string;
  /** Which callee fired (symlink / symlinkSync / readFile / open …). */
  calleeName: string;
  /** For symlink-creation: the matched sensitive path substring. */
  sensitiveTarget: string | null;
  /** For symlink-creation: whether the link path targets an attacker-reachable config dir. */
  linkPathInAttackerDir: boolean;
  /** For unguarded-read: whether a realpath-family guard was observed in scope. */
  guardPresent: boolean;
  /** For unguarded-read: whether a NOFOLLOW flag was observed in scope. */
  nofollowPresent: boolean;
  /** File path from the gathered source. */
  file: string;
}

export interface L6GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: L6Fact[];
}

export function gatherL6(context: AnalysisContext): L6GatherResult {
  const files = collectFiles(context);
  if (files.size === 0) return { mode: "absent", facts: [] };

  const facts: L6Fact[] = [];
  for (const [file, text] of files) {
    if (isTestFileShape(file, text)) continue;
    facts.push(...scanFile(file, text));
  }
  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}

function collectFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}

function isTestFileShape(file: string, text: string): boolean {
  if (file.endsWith(".test.ts") || file.endsWith(".test.js")) return true;
  if (file.endsWith(".spec.ts") || file.endsWith(".spec.js")) return true;
  if (file.includes("__tests__/") || file.includes("__fixtures__/")) return true;
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"');
  const hasSuite = text.includes("describe(");
  return hasRunner && hasSuite;
}

function scanFile(file: string, text: string): L6Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const out: L6Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    const symCreation = detectSymlinkCreation(node, sf, file);
    if (symCreation) out.push(symCreation);

    const unguarded = detectUnguardedRead(node, sf, file);
    if (unguarded) out.push(unguarded);

    ts.forEachChild(node, visit);
  });

  return out;
}

// ─── Symlink creation detection ────────────────────────────────────────────

function detectSymlinkCreation(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): L6Fact | null {
  if (!ts.isCallExpression(node)) return null;
  const calleeName = resolveCalleeName(node);
  if (!calleeName || !SYMLINK_CREATE_CALLEES.has(calleeName)) return null;

  // fs.symlink(target, linkpath)
  const targetArg = node.arguments[0];
  const linkpathArg = node.arguments[1];
  if (!targetArg || !linkpathArg) return null;

  const targetText = readStringLiteral(targetArg);
  if (!targetText) return null;

  const sensitive = matchSensitivePath(targetText);
  if (!sensitive) return null;

  const linkpathText = readStringLiteral(linkpathArg) ?? linkpathArg.getText(sf);
  const linkPathInAttackerDir = pathLooksLikeAttackerReachableConfig(linkpathText);

  const { line, col } = toLineCol(sf, node.getStart(sf));
  return {
    kind: "symlink-creation",
    location: { kind: "source", file, line, col },
    observed: node.getText(sf).slice(0, 200),
    calleeName,
    sensitiveTarget: sensitive,
    linkPathInAttackerDir,
    guardPresent: false,
    nofollowPresent: false,
    file,
  };
}

function matchSensitivePath(text: string): string | null {
  for (const tok of SENSITIVE_TARGET_PATHS) {
    if (text.includes(tok)) return tok;
  }
  return null;
}

function pathLooksLikeAttackerReachableConfig(text: string): boolean {
  for (const tok of ATTACKER_REACHABLE_CONFIG_DIRS) {
    if (text.includes(tok)) return true;
  }
  return false;
}

// ─── Unguarded-read detection ──────────────────────────────────────────────

function detectUnguardedRead(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): L6Fact | null {
  if (!ts.isCallExpression(node)) return null;
  const calleeName = resolveCalleeName(node);
  if (!calleeName || !READ_CALLEES.has(calleeName)) return null;

  // First argument must be a non-literal expression (user-controlled).
  const pathArg = node.arguments[0];
  if (!pathArg) return null;
  if (
    ts.isStringLiteral(pathArg) ||
    ts.isNoSubstitutionTemplateLiteral(pathArg)
  ) {
    // Hard-coded path: not attacker-controlled. Skip.
    return null;
  }

  // Enclosing function scope text — used to check for mitigations.
  const enclosingText = getEnclosingFunctionText(node, sf);
  const guardPresent = functionHasGuardCall(enclosingText);
  const nofollowPresent = functionHasNofollowFlag(enclosingText, node, sf);

  // Both mitigations present → no finding.
  if (guardPresent && nofollowPresent) return null;
  // At least one mitigation present AND callee is safe form (lstat preceded read in same scope)?
  // We DO emit a finding for partial mitigations — escalated-to-high severity — because
  // CVE-2025-53109 class requires BOTH realpath AND root-containment.
  // The rule's index.ts downgrades severity when guardPresent is true.

  const { line, col } = toLineCol(sf, node.getStart(sf));
  return {
    kind: "unguarded-read",
    location: { kind: "source", file, line, col },
    observed: node.getText(sf).slice(0, 200),
    calleeName,
    sensitiveTarget: null,
    linkPathInAttackerDir: false,
    guardPresent,
    nofollowPresent,
    file,
  };
}

function functionHasGuardCall(bodyText: string): boolean {
  for (const guard of SYMLINK_GUARD_CALLEES) {
    if (bodyText.includes(`.${guard}(`) || bodyText.includes(` ${guard}(`)) return true;
  }
  return false;
}

function functionHasNofollowFlag(
  bodyText: string,
  callNode: ts.CallExpression,
  sf: ts.SourceFile,
): boolean {
  for (const tok of NOFOLLOW_FLAG_TOKENS) {
    if (bodyText.includes(tok)) return true;
  }
  // Also accept the numeric flag if the call site passes a constant identifier we
  // don't recognise — conservative, but the declared vocab is in data/.
  for (const arg of callNode.arguments) {
    const argText = arg.getText(sf);
    for (const tok of NOFOLLOW_FLAG_TOKENS) {
      if (argText.includes(tok)) return true;
    }
  }
  return false;
}

function getEnclosingFunctionText(node: ts.Node, sf: ts.SourceFile): string {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (
      ts.isFunctionDeclaration(current) ||
      ts.isFunctionExpression(current) ||
      ts.isArrowFunction(current) ||
      ts.isMethodDeclaration(current) ||
      ts.isConstructorDeclaration(current)
    ) {
      return current.getText(sf);
    }
    current = current.parent;
  }
  return sf.text; // module scope
}

// ─── AST helpers ──────────────────────────────────────────────────────────

function resolveCalleeName(call: ts.CallExpression): string | null {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

function readStringLiteral(node: ts.Node): string | null {
  if (ts.isStringLiteral(node)) return node.text;
  if (ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function toLineCol(sf: ts.SourceFile, pos: number): { line: number; col: number } {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return { line: line + 1, col: character + 1 };
}
