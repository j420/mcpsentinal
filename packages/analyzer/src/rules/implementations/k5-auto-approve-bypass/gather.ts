/**
 * K5 — Auto-Approve / Bypass Confirmation: deterministic AST fact gatherer.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  AUTO_APPROVE_TOKENS,
  CONFIRMATION_FUNCTION_NAMES,
  ENV_VAR_BYPASS_TOKENS,
} from "./data/bypass-vocabulary.js";

export type K5FactKind =
  | "bypass-flag-assignment"
  | "env-var-bypass"
  | "neutered-stub";

export interface K5Fact {
  kind: K5FactKind;
  location: Location;
  observed: string;
  tokenHit: string;
  file: string;
  hasApprovalPath: boolean;
}

export interface K5GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: K5Fact[];
}

export function gatherK5(context: AnalysisContext): K5GatherResult {
  const files = collectFiles(context);
  if (files.size === 0) return { mode: "absent", facts: [] };

  const allFacts: K5Fact[] = [];
  let anyScanned = false;
  for (const [file, text] of files) {
    if (isTestFileShape(file, text)) continue;
    anyScanned = true;
    allFacts.push(...scanFile(file, text));
  }
  if (!anyScanned) return { mode: "test-file", facts: [] };
  return { mode: allFacts.length > 0 ? "facts" : "absent", facts: allFacts };
}

function collectFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) out.set("<concatenated-source>", context.source_code);
  return out;
}

function isTestFileShape(file: string, text: string): boolean {
  if (
    file.endsWith(".test.ts") ||
    file.endsWith(".spec.ts") ||
    file.endsWith(".test.js") ||
    file.endsWith(".spec.js") ||
    file.includes("__tests__/") ||
    file.includes("__fixtures__/")
  ) {
    return true;
  }
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"');
  const hasSuite =
    text.includes("describe(") || text.includes("it(") || text.includes("test(");
  return hasRunner && hasSuite;
}

function scanFile(file: string, text: string): K5Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const hasApprovalPath = detectHonestApproval(sf);
  const facts: K5Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken
    ) {
      const fact = detectFlagAssignment(node, sf, file, hasApprovalPath);
      if (fact) facts.push(fact);
    }

    if (ts.isPropertyAssignment(node)) {
      const fact = detectObjectPropertyFlag(node, sf, file, hasApprovalPath);
      if (fact) facts.push(fact);
    }

    if (ts.isVariableDeclaration(node)) {
      const fact = detectVariableFlag(node, sf, file, hasApprovalPath);
      if (fact) facts.push(fact);
    }

    if (ts.isPropertyAccessExpression(node)) {
      const fact = detectEnvVarBypass(node, sf, file, hasApprovalPath);
      if (fact) facts.push(fact);
    }

    if (ts.isFunctionDeclaration(node)) {
      const fact = detectStubFunction(node, sf, file, hasApprovalPath);
      if (fact) facts.push(fact);
    }
    if (ts.isVariableStatement(node)) {
      for (const decl of node.declarationList.declarations) {
        const fact = detectStubArrow(decl, sf, file, hasApprovalPath);
        if (fact) facts.push(fact);
      }
    }

    ts.forEachChild(node, visit);
  });

  return dedupe(facts);
}

function detectFlagAssignment(
  node: ts.BinaryExpression,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (node.right.kind !== ts.SyntaxKind.TrueKeyword) return null;
  const name = extractAssignmentName(node.left);
  if (!name) return null;
  const tok = matchAutoApproveToken(name);
  if (!tok) return null;
  return {
    kind: "bypass-flag-assignment",
    location: locFromNode(sf, file, node),
    observed: node.getText(sf).slice(0, 200),
    tokenHit: tok,
    file,
    hasApprovalPath,
  };
}

function detectObjectPropertyFlag(
  node: ts.PropertyAssignment,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (node.initializer.kind !== ts.SyntaxKind.TrueKeyword) return null;
  const name = propertyKeyText(node.name);
  if (!name) return null;
  const tok = matchAutoApproveToken(name);
  if (!tok) return null;
  return {
    kind: "bypass-flag-assignment",
    location: locFromNode(sf, file, node),
    observed: node.getText(sf).slice(0, 200),
    tokenHit: tok,
    file,
    hasApprovalPath,
  };
}

function detectVariableFlag(
  node: ts.VariableDeclaration,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (!node.initializer) return null;
  if (node.initializer.kind !== ts.SyntaxKind.TrueKeyword) return null;
  if (!ts.isIdentifier(node.name)) return null;
  const tok = matchAutoApproveToken(node.name.text);
  if (!tok) return null;
  return {
    kind: "bypass-flag-assignment",
    location: locFromNode(sf, file, node),
    observed: node.getText(sf).slice(0, 200),
    tokenHit: tok,
    file,
    hasApprovalPath,
  };
}

function detectEnvVarBypass(
  node: ts.PropertyAccessExpression,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (!ts.isPropertyAccessExpression(node.expression)) return null;
  const outerName = node.name.text;
  const inner = node.expression;
  const innerName = inner.name.text;
  const root = inner.expression;
  if (!ts.isIdentifier(root)) return null;
  if (root.text !== "process" || innerName !== "env") return null;
  for (const tok of ENV_VAR_BYPASS_TOKENS) {
    if (outerName.toUpperCase().includes(tok)) {
      return {
        kind: "env-var-bypass",
        location: locFromNode(sf, file, node),
        observed: node.getText(sf).slice(0, 200),
        tokenHit: `process.env.${outerName}`,
        file,
        hasApprovalPath,
      };
    }
  }
  return null;
}

function detectStubFunction(
  node: ts.FunctionDeclaration,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (!node.name) return null;
  if (!CONFIRMATION_FUNCTION_NAMES.has(node.name.text)) return null;
  if (!returnsTrueUnconditionally(node.body)) return null;
  return {
    kind: "neutered-stub",
    location: locFromNode(sf, file, node),
    observed: node.getText(sf).slice(0, 220),
    tokenHit: node.name.text,
    file,
    hasApprovalPath,
  };
}

function detectStubArrow(
  decl: ts.VariableDeclaration,
  sf: ts.SourceFile,
  file: string,
  hasApprovalPath: boolean,
): K5Fact | null {
  if (!ts.isIdentifier(decl.name)) return null;
  if (!CONFIRMATION_FUNCTION_NAMES.has(decl.name.text)) return null;
  if (!decl.initializer) return null;
  const fn = decl.initializer;
  if (!ts.isArrowFunction(fn) && !ts.isFunctionExpression(fn)) return null;
  if (ts.isArrowFunction(fn) && !ts.isBlock(fn.body)) {
    if (expressionIsTrue(fn.body)) {
      return {
        kind: "neutered-stub",
        location: locFromNode(sf, file, decl),
        observed: decl.getText(sf).slice(0, 220),
        tokenHit: decl.name.text,
        file,
        hasApprovalPath,
      };
    }
    return null;
  }
  if (!returnsTrueUnconditionally((fn as ts.ArrowFunction).body as ts.Block | undefined)) {
    return null;
  }
  return {
    kind: "neutered-stub",
    location: locFromNode(sf, file, decl),
    observed: decl.getText(sf).slice(0, 220),
    tokenHit: decl.name.text,
    file,
    hasApprovalPath,
  };
}

function extractAssignmentName(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  return null;
}

function propertyKeyText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

function matchAutoApproveToken(name: string): string | null {
  const lower = name.toLowerCase();
  for (const tok of AUTO_APPROVE_TOKENS) {
    if (lower.includes(tok.toLowerCase())) return tok;
  }
  return null;
}

function returnsTrueUnconditionally(body: ts.Block | undefined): boolean {
  if (!body) return false;
  if (body.statements.length !== 1) return false;
  const only = body.statements[0];
  if (!ts.isReturnStatement(only) || !only.expression) return false;
  return expressionIsTrue(only.expression);
}

function expressionIsTrue(expr: ts.Expression): boolean {
  if (expr.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (
    ts.isCallExpression(expr) &&
    ts.isPropertyAccessExpression(expr.expression) &&
    ts.isIdentifier(expr.expression.expression) &&
    expr.expression.expression.text === "Promise" &&
    expr.expression.name.text === "resolve" &&
    expr.arguments[0]?.kind === ts.SyntaxKind.TrueKeyword
  ) {
    return true;
  }
  return false;
}

function detectHonestApproval(sf: ts.SourceFile): boolean {
  const text = sf.text;
  for (const name of CONFIRMATION_FUNCTION_NAMES) {
    if (text.includes(`${name}(`)) return true;
  }
  return false;
}

function locFromNode(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function dedupe(facts: K5Fact[]): K5Fact[] {
  const seen = new Set<string>();
  const out: K5Fact[] = [];
  for (const f of facts) {
    const key =
      f.location.kind === "source"
        ? `${f.kind}|${f.location.file}|${f.location.line}|${f.location.col ?? 0}|${f.tokenHit}`
        : `${f.kind}|${f.tokenHit}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
