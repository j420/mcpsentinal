/** M8 gather — AST only; zero regex. */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  DECODE_FUNCTIONS,
  DECODE_FUNCTIONS_EXTRA,
  INPUT_SOURCE_TOKENS,
  INPUT_SOURCE_TOKENS_EXTRA,
  POST_DECODE_VALIDATORS,
  POST_DECODE_VALIDATORS_EXTRA,
  type DecodeFunctionSpec,
} from "./data/decode-vocabulary.js";

const ALL_DECODES: Readonly<Record<string, DecodeFunctionSpec>> = {
  ...DECODE_FUNCTIONS,
  ...DECODE_FUNCTIONS_EXTRA,
};
const DECODE_NAMES: ReadonlySet<string> = new Set(Object.keys(ALL_DECODES));

const INPUT_TOKENS: ReadonlySet<string> = new Set(
  [...INPUT_SOURCE_TOKENS, ...INPUT_SOURCE_TOKENS_EXTRA].map((s) => s.toLowerCase()),
);
const VALIDATORS: ReadonlySet<string> = new Set([
  ...POST_DECODE_VALIDATORS,
  ...POST_DECODE_VALIDATORS_EXTRA,
]);

export interface EncodingSite {
  readonly location: Location;
  readonly decode_name: string;
  readonly observed: string;
  readonly enclosing_function_location: Location | null;
  readonly has_validator_after: boolean;
}

function getCallee(node: ts.CallExpression, sf: ts.SourceFile): string | null {
  if (ts.isIdentifier(node.expression)) return node.expression.text;
  if (ts.isPropertyAccessExpression(node.expression)) {
    return `${node.expression.expression.getText(sf)}.${node.expression.name.text}`;
  }
  return null;
}

function argTextContainsInputToken(node: ts.CallExpression, sf: ts.SourceFile): boolean {
  for (const arg of node.arguments) {
    const text = arg.getText(sf).toLowerCase();
    for (const tok of INPUT_TOKENS) {
      if (text.includes(tok)) return true;
    }
  }
  return false;
}

function bufferFromIsBase64(node: ts.CallExpression): boolean {
  if (node.arguments.length < 2) return false;
  const second = node.arguments[1];
  if (ts.isStringLiteral(second) || ts.isNoSubstitutionTemplateLiteral(second)) {
    return second.text.toLowerCase() === "base64";
  }
  return false;
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

function hasValidatorAfter(fn: ts.Node, sf: ts.SourceFile, decodePos: number): boolean {
  const fnText = fn.getText(sf);
  const after = fnText.slice(decodePos);
  const afterLower = after.toLowerCase();
  for (const v of VALIDATORS) {
    if (afterLower.includes(v)) return true;
  }
  return false;
}

export function gatherM8(context: AnalysisContext): EncodingSite[] {
  const out: EncodingSite[] = [];
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
      if (ts.isCallExpression(node)) {
        const callee = getCallee(node, sf);
        if (callee !== null && DECODE_NAMES.has(callee)) {
          const spec = ALL_DECODES[callee]!;
          // Buffer.from: must have encoding='base64'
          if (spec.arg_constraint === "base64-literal" && !bufferFromIsBase64(node)) {
            ts.forEachChild(node, visit);
            return;
          }
          if (argTextContainsInputToken(node, sf)) {
            const fn = getEnclosingFunc(node);
            if (fn !== null) {
              const fnStart = fn.getStart(sf);
              const decodePos = node.getStart(sf) - fnStart;
              const hasValidator = hasValidatorAfter(fn, sf, decodePos);
              if (!hasValidator) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                const fnLine = sf.getLineAndCharacterOfPosition(fnStart).line + 1;
                out.push({
                  location: { kind: "source", file, line },
                  decode_name: callee,
                  observed: text.split("\n")[line - 1]?.trim().slice(0, 120) ?? "",
                  enclosing_function_location: { kind: "source", file, line: fnLine },
                  has_validator_after: false,
                });
              }
            }
          }
        }
      }
      ts.forEachChild(node, visit);
    };

    ts.forEachChild(sf, visit);
  }
  return out;
}
