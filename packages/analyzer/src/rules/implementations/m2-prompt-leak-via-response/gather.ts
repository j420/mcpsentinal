/** M2 gather — AST-only; zero regex. */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SYSTEM_PROMPT_IDENTIFIERS,
  SYSTEM_PROMPT_IDENTIFIERS_EXTRA,
  RESPONSE_SINK_METHODS,
  RESPONSE_SINK_METHODS_EXTRA,
  REDACTION_TOKENS,
  REDACTION_TOKENS_EXTRA,
} from "./data/prompt-vocabulary.js";

const PROMPT_SET: ReadonlySet<string> = new Set([
  ...SYSTEM_PROMPT_IDENTIFIERS,
  ...SYSTEM_PROMPT_IDENTIFIERS_EXTRA,
]);
const SINK_SET: ReadonlySet<string> = new Set([
  ...RESPONSE_SINK_METHODS,
  ...RESPONSE_SINK_METHODS_EXTRA,
]);
const REDACTION_SET: ReadonlySet<string> = new Set([
  ...REDACTION_TOKENS,
  ...REDACTION_TOKENS_EXTRA,
]);

export interface LeakSite {
  readonly location: Location;
  readonly identifier: string;
  readonly observed: string;
  readonly enclosing_has_redaction: boolean;
  readonly enclosing_function_location: Location | null;
}

function getEnclosingFunc(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    ) return cur;
    cur = cur.parent;
  }
  return null;
}

function hasRedactionInScope(fn: ts.Node): boolean {
  let found = false;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n) && REDACTION_SET.has(n.text)) {
      found = true;
      return;
    }
    if (ts.isPropertyAccessExpression(n) && REDACTION_SET.has(n.name.text)) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(fn, visit);
  return found;
}

/** Return true if this identifier node is part of a data-flow into a response. */
function isInResponsePath(node: ts.Node): { ok: boolean; how: string } {
  let cur: ts.Node | undefined = node.parent;
  let depth = 0;
  while (cur && depth < 8) {
    if (ts.isReturnStatement(cur)) return { ok: true, how: "return statement" };
    if (
      ts.isCallExpression(cur) &&
      ts.isPropertyAccessExpression(cur.expression) &&
      SINK_SET.has(cur.expression.name.text)
    ) {
      return { ok: true, how: `response.${cur.expression.name.text}()` };
    }
    if (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      // assignment — traverse one more hop to find return downstream
      return { ok: true, how: "variable assignment towards response" };
    }
    if (
      ts.isShorthandPropertyAssignment(cur) ||
      ts.isPropertyAssignment(cur) ||
      ts.isSpreadAssignment(cur) ||
      ts.isSpreadElement(cur) ||
      ts.isTemplateSpan(cur) ||
      (ts.isBinaryExpression(cur) && cur.operatorToken.kind === ts.SyntaxKind.PlusToken)
    ) {
      cur = cur.parent;
      depth++;
      continue;
    }
    cur = cur.parent;
    depth++;
  }
  return { ok: false, how: "" };
}

export function gatherM2(context: AnalysisContext): LeakSite[] {
  const out: LeakSite[] = [];
  const files = context.source_files ?? (context.source_code ? new Map([["scan.ts", context.source_code]]) : new Map());

  for (const [file, text] of files) {
    if (!text) continue;
    let sf: ts.SourceFile;
    try {
      sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
    } catch {
      continue;
    }

    const visit = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && PROMPT_SET.has(node.text)) {
        const { ok, how } = isInResponsePath(node);
        if (ok) {
          const fn = getEnclosingFunc(node);
          const redaction = fn !== null && hasRedactionInScope(fn);
          if (!redaction) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            const lineText = text.split("\n")[line - 1]?.trim().slice(0, 120) ?? "";
            const fnLine = fn
              ? sf.getLineAndCharacterOfPosition(fn.getStart(sf)).line + 1
              : null;
            out.push({
              location: { kind: "source", file, line },
              identifier: node.text,
              observed: `${lineText}  /* via ${how} */`,
              enclosing_has_redaction: false,
              enclosing_function_location: fnLine !== null
                ? { kind: "source", file, line: fnLine }
                : null,
            });
          }
        }
      }
      ts.forEachChild(node, visit);
    };

    ts.forEachChild(sf, visit);
  }
  return out;
}
