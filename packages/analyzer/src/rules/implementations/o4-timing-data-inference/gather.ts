/**
 * O4 evidence gathering — AST-based (no regex).
 *
 * Walks the TypeScript/JavaScript AST, finds delay-like call expressions,
 * then inspects each enclosing function for:
 *   - data-dependent identifiers (sensitive source: secret, password, etc.)
 *   - timing-safe mitigations (crypto.timingSafeEqual, Math.random jitter)
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  DELAY_FUNCTION_NAMES,
  DATA_DEPENDENT_IDENTIFIERS,
  DATA_DEPENDENT_CONDITIONS,
  TIMING_SAFE_IDENTIFIERS,
  JITTER_CALLEE,
} from "./data/timing-vocabulary.js";

export interface TimingSite {
  readonly location: Location;
  readonly delayCallee: string;
  readonly delayKind: string;
  readonly observed: string;
  readonly hasDataDependentIdentifier: boolean;
  readonly hasTimingSafe: boolean;
  readonly hasJitter: boolean;
  readonly enclosingFunctionLocation: Location | null;
}

const SENSITIVE_SET: ReadonlySet<string> = new Set([
  ...DATA_DEPENDENT_IDENTIFIERS,
  ...DATA_DEPENDENT_CONDITIONS,
]);
const TIMING_SAFE_SET: ReadonlySet<string> = new Set(TIMING_SAFE_IDENTIFIERS);
const DELAY_NAMES: ReadonlySet<string> = new Set(Object.keys(DELAY_FUNCTION_NAMES));

export function isTestSource(sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression)) {
      const name = n.expression.text;
      if (name === "describe" || name === "it" || name === "test") {
        found = true;
        return;
      }
    }
    if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
      const m = n.moduleSpecifier.text;
      if (m === "vitest" || m === "jest" || m === "@jest/globals") {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(sf, visit);
  return found;
}

function getEnclosingFunc(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

function hasSensitiveIdentifier(fnNode: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n) && SENSITIVE_SET.has(n.text)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(fnNode, visit);
  return found;
}

function hasTimingSafe(fnNode: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n) && TIMING_SAFE_SET.has(n.text)) {
      found = true;
      return;
    }
    // Property access like hmac.compare_digest
    if (ts.isPropertyAccessExpression(n) && TIMING_SAFE_SET.has(n.name.text)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(fnNode, visit);
  return found;
}

function hasJitterCall(fnNode: ts.Node, sf: ts.SourceFile): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    // Match Math.random() anywhere in a BinaryExpression (additive jitter)
    if (ts.isBinaryExpression(n)) {
      const bothSides = `${n.left.getText(sf)} ${n.right.getText(sf)}`;
      if (bothSides.includes(JITTER_CALLEE)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(fnNode, visit);
  return found;
}

function getDelayCallee(node: ts.CallExpression, sf: ts.SourceFile): string | null {
  // Simple identifier: setTimeout(...)
  if (ts.isIdentifier(node.expression)) {
    const name = node.expression.text;
    if (DELAY_NAMES.has(name)) return name;
  }
  // Property access: x.setTimeout(...) or Promise.resolve().then(...).delay()
  if (ts.isPropertyAccessExpression(node.expression)) {
    const name = node.expression.name.text;
    if (DELAY_NAMES.has(name)) return name;
  }
  // NewExpression: `new Promise(resolve => setTimeout(resolve, ...))` —
  // the inner setTimeout is a separate CallExpression we'll visit later.
  return null;
}

export function gatherO4(context: AnalysisContext, file: string): TimingSite[] {
  if (!context.source_code) return [];
  const text = context.source_code;
  const sites: TimingSite[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  if (isTestSource(sf)) return [];

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const callee = getDelayCallee(node, sf);
      if (callee !== null) {
        const enc = getEnclosingFunc(node);
        const spec = DELAY_FUNCTION_NAMES[callee]!;
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        const location: Location = { kind: "source", file, line };
        const observed = text.split("\n")[line - 1]?.trim().slice(0, 120) ?? "";

        const sensitive = enc ? hasSensitiveIdentifier(enc) : false;
        const timingSafe = enc ? hasTimingSafe(enc) : false;
        const jitter = enc ? hasJitterCall(enc, sf) : false;

        if (sensitive) {
          const fnStart = enc ? sf.getLineAndCharacterOfPosition(enc.getStart(sf)).line + 1 : null;
          const fnLoc: Location | null = fnStart !== null
            ? { kind: "source", file, line: fnStart }
            : null;

          sites.push({
            location,
            delayCallee: callee,
            delayKind: spec.kind,
            observed,
            hasDataDependentIdentifier: true,
            hasTimingSafe: timingSafe,
            hasJitter: jitter,
            enclosingFunctionLocation: fnLoc,
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return sites;
}
