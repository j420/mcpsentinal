/**
 * Q7 gather step — detects three DXT / extension privilege-chain
 * ingress points in source code.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  AUTO_APPROVE_KEYS,
  BRIDGE_METHOD_NAMES,
  IPC_RECEIVERS,
  NATIVE_MESSAGING_ROOTS,
} from "./data/vocabulary.js";

const AUTO_APPROVE_SET: ReadonlySet<string> = new Set(Object.keys(AUTO_APPROVE_KEYS));
const BRIDGE_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(BRIDGE_METHOD_NAMES));
const IPC_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(IPC_RECEIVERS));
const NATIVE_ROOT_SET: ReadonlySet<string> = new Set(Object.keys(NATIVE_MESSAGING_ROOTS));

export type DxtPrivilegeHitKind =
  | "auto-approve-flag"
  | "native-messaging-bridge"
  | "ipc-handler";

export interface DxtPrivilegeSite {
  kind: DxtPrivilegeHitKind;
  /** Matched property / method / receiver name. */
  marker: string;
  location: Location;
  observed: string;
}

export interface Q7Gathered {
  sites: DxtPrivilegeSite[];
}

export function gatherQ7(context: AnalysisContext): Q7Gathered {
  const text = context.source_code;
  if (!text) return { sites: [] };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  const sites: DxtPrivilegeSite[] = [];

  ts.forEachChild(sf, function visit(node) {
    // Auto-approve: { autoApprove: true } or { "autoApprove": true } inside
    // any object literal.
    if (ts.isPropertyAssignment(node)) {
      const name = propName(node.name);
      if (name && AUTO_APPROVE_SET.has(name)) {
        if (isTrueLiteral(node.initializer)) {
          sites.push({
            kind: "auto-approve-flag",
            marker: name,
            location: sourceLocation(sf, node),
            observed: `${name}: true`,
          });
        }
      }
    }

    // CallExpression-based ingress: native messaging or ipcMain.handle
    if (ts.isCallExpression(node)) {
      const classified = classifyCall(node);
      if (classified) {
        sites.push({
          ...classified,
          location: sourceLocation(sf, node),
          observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
        });
      }
    }
    ts.forEachChild(node, visit);
  });

  return { sites };
}

function propName(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

function isTrueLiteral(expr: ts.Expression): boolean {
  return expr.kind === ts.SyntaxKind.TrueKeyword;
}

function classifyCall(
  call: ts.CallExpression,
): { kind: DxtPrivilegeHitKind; marker: string } | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text.toLowerCase();
  if (!BRIDGE_METHOD_SET.has(method)) return null;

  // native-messaging: chrome.runtime.sendNativeMessage / browser.runtime.sendNativeMessage
  if (method === "sendnativemessage") {
    const rootPath = expressionPath(call.expression.expression);
    if (rootPath && NATIVE_ROOT_SET.has(rootPath)) {
      return { kind: "native-messaging-bridge", marker: rootPath };
    }
  }

  // ipcMain.handle
  if (method === "handle") {
    const recv = call.expression.expression;
    if (ts.isIdentifier(recv) && IPC_RECEIVER_SET.has(recv.text.toLowerCase())) {
      return { kind: "ipc-handler", marker: recv.text };
    }
  }
  return null;
}

function expressionPath(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    const head = expressionPath(expr.expression);
    if (head === null) return null;
    return `${head}.${expr.name.text}`;
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
