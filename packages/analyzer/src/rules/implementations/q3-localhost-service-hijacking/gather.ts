/**
 * Q3 gather step — AST detection of listener binds on a localhost
 * host without an auth check in the enclosing scope.
 *
 * Zero regex. Honest-refusal gate: if the source contains no
 * listener-method call at all, returns `[]`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  LOCALHOST_HOST_VALUES,
  LISTENER_METHODS,
  MCP_RECEIVER_TOKENS,
  AUTH_TOKEN_SCOPE_IDS,
} from "./data/vocabulary.js";

const LOCALHOST_VALUE_SET: ReadonlySet<string> = new Set(
  Object.keys(LOCALHOST_HOST_VALUES),
);
const LISTENER_SET: ReadonlySet<string> = new Set(Object.keys(LISTENER_METHODS));
const MCP_TOKEN_SET: ReadonlySet<string> = new Set(Object.keys(MCP_RECEIVER_TOKENS));
const AUTH_ID_SET: ReadonlySet<string> = new Set(Object.keys(AUTH_TOKEN_SCOPE_IDS));

export interface LocalhostBindSite {
  /** Which host literal triggered the match. */
  host: string;
  /** Whether an MCP-related token appears on the receiver chain. */
  mcpTokenOnReceiver: boolean;
  /** Whether an auth identifier appears in the enclosing function. */
  enclosingHasAuth: boolean;
  /** Matched auth identifier, if any. */
  matchedAuth: string | null;
  /** Source-kind Location of the listener call. */
  location: Location;
  /** Enclosing function location. */
  enclosingFunctionLocation: Location | null;
  /** Narrative snippet. */
  observed: string;
}

export interface Q3Gathered {
  sites: LocalhostBindSite[];
  /** True when NO listener-call was observed at all — honest refusal. */
  noNetworkBinding: boolean;
}

export function gatherQ3(context: AnalysisContext): Q3Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], noNetworkBinding: true };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  const sites: LocalhostBindSite[] = [];
  let anyListenerCall = false;

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const methodName = listenerMethodName(node);
      if (methodName) {
        anyListenerCall = true;
        const hostLiteral = findHostArgument(node);
        if (hostLiteral && LOCALHOST_VALUE_SET.has(hostLiteral.toLowerCase())) {
          const mcpOnReceiver = receiverMentionsMcp(node);
          const enclosing = findEnclosingFunction(node);
          const auth = enclosing ? findAuthInScope(enclosing) : null;
          sites.push({
            host: hostLiteral.toLowerCase(),
            mcpTokenOnReceiver: mcpOnReceiver,
            enclosingHasAuth: auth !== null,
            matchedAuth: auth,
            location: sourceLocation(sf, node),
            enclosingFunctionLocation: enclosing ? sourceLocation(sf, enclosing) : null,
            observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  });

  return { sites, noNetworkBinding: !anyListenerCall };
}

function listenerMethodName(call: ts.CallExpression): string | null {
  if (ts.isPropertyAccessExpression(call.expression)) {
    const m = call.expression.name.text.toLowerCase();
    return LISTENER_SET.has(m) ? m : null;
  }
  if (ts.isIdentifier(call.expression)) {
    const m = call.expression.text.toLowerCase();
    return LISTENER_SET.has(m) ? m : null;
  }
  return null;
}

function findHostArgument(call: ts.CallExpression): string | null {
  for (const arg of call.arguments) {
    if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
      return arg.text;
    }
  }
  return null;
}

function receiverMentionsMcp(call: ts.CallExpression): boolean {
  let cur: ts.Node = call.expression;
  while (cur) {
    if (ts.isIdentifier(cur)) {
      if (MCP_TOKEN_SET.has(cur.text.toLowerCase())) return true;
      break;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      if (MCP_TOKEN_SET.has(cur.name.text.toLowerCase())) return true;
      cur = cur.expression;
      continue;
    }
    if (ts.isCallExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    break;
  }
  return false;
}

function findAuthInScope(enclosing: ts.Node): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && AUTH_ID_SET.has(n.text)) {
      found = n.text;
      return;
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(enclosing, visit);
  return found;
}

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

function sourceLocation(sf: ts.SourceFile, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return {
    kind: "source",
    file: sf.fileName,
    line: line + 1,
    col: character + 1,
  };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  return sf.text.split("\n")[line] ?? "";
}
