/**
 * N10 — Deterministic fact gathering for incomplete-handshake DoS.
 *
 * Detects calls constructing a connection-accepting server (WebSocketServer,
 * http.createServer, net.createServer, listen) whose enclosing function does
 * not contain any timeout/deadline/maxConnections vocabulary.
 */

import ts from "typescript";
import {
  SERVER_ACCEPT_CONSTRUCTORS,
  TIMEOUT_PRIMITIVES,
  CONNECTION_LIMITS,
} from "./data/handshake-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export type HandshakeAcceptKind =
  | "websocket-server"
  | "http-create-server"
  | "net-create-server"
  | "app-listen"
  | "upgrade-handler";

export interface HandshakeFact {
  readonly location: SourceLocation;
  readonly accept_kind: HandshakeAcceptKind;
  readonly accept_expression: string;
  readonly enclosing_function_text: string;
  readonly timeout_present: boolean;
  readonly connection_limit_present: boolean;
}

export interface GatheredFacts {
  readonly facts: HandshakeFact[];
  readonly parse_succeeded: boolean;
}

/** Strip JS/TS single-line and block comments so vocabulary checks ignore prose. */
function stripComments(text: string): string {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    if (text[i] === "/" && text[i + 1] === "/") {
      // line comment — skip to newline
      while (i < n && text[i] !== "\n") i++;
    } else if (text[i] === "/" && text[i + 1] === "*") {
      // block comment — skip to closing */
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
    } else if (text[i] === '"' || text[i] === "'" || text[i] === "`") {
      // preserve string literals (they may still legitimately contain keywords)
      const quote = text[i];
      out += text[i];
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === "\\" && i + 1 < n) {
          out += text[i];
          out += text[i + 1];
          i += 2;
          continue;
        }
        out += text[i];
        i++;
      }
      if (i < n) {
        out += text[i];
        i++;
      }
    } else {
      out += text[i];
      i++;
    }
  }
  return out;
}

function tokenSet(text: string): Set<string> {
  const cleaned = stripComments(text);
  const out = new Set<string>();
  let cur = "";
  for (const ch of cleaned) {
    const isWord = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9") || ch === "_";
    if (isWord) cur += ch;
    else {
      if (cur) out.add(cur.toLowerCase());
      cur = "";
    }
  }
  if (cur) out.add(cur.toLowerCase());
  return out;
}

function containsTimeoutVocabulary(text: string): boolean {
  const cleaned = stripComments(text);
  const tokens = tokenSet(cleaned);
  for (const key of Object.keys(TIMEOUT_PRIMITIVES)) {
    const normalised = key.toLowerCase();
    if (tokens.has(normalised)) return true;
  }
  // Catch compound forms the tokeniser splits apart.
  if (cleaned.includes("AbortSignal.timeout")) return true;
  if (cleaned.includes("Promise.race")) return true;
  if (cleaned.includes("setTimeout(")) return true;
  return false;
}

function containsConnectionLimitVocabulary(text: string): boolean {
  const tokens = tokenSet(text);
  for (const key of Object.keys(CONNECTION_LIMITS)) {
    if (tokens.has(key.toLowerCase())) return true;
  }
  return false;
}

function classifyAccept(expressionText: string): HandshakeAcceptKind | null {
  if (expressionText.includes("WebSocketServer")) return "websocket-server";
  // http.createServer or https.createServer
  if (/\bhttp\b/.test(expressionText) && expressionText.endsWith("createServer")) return "http-create-server";
  if (/\bhttps\b/.test(expressionText) && expressionText.endsWith("createServer")) return "http-create-server";
  if (/\bnet\b/.test(expressionText) && expressionText.endsWith("createServer")) return "net-create-server";
  // Generic createServer call — treat as http accept.
  if (expressionText === "createServer") return "http-create-server";
  if (expressionText.endsWith(".listen")) return "app-listen";
  if (expressionText.endsWith(".upgrade")) return "upgrade-handler";
  return null;
}

function enclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isSourceFile(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

function makeLocation(node: ts.Node, sf: ts.SourceFile, source: string): SourceLocation {
  const start = node.getStart(sf);
  const pos = sf.getLineAndCharacterOfPosition(start);
  const line = pos.line + 1;
  const column = pos.character + 1;
  const lineText = source.split("\n")[line - 1] ?? "";
  const encl = enclosingFunction(node);
  const enclName =
    encl && ts.isFunctionDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : encl && ts.isMethodDeclaration(encl) && encl.name
      ? encl.name.getText(sf)
      : null;
  return {
    kind: "source_code_line",
    line,
    column,
    snippet: lineText.trim().slice(0, 200),
    enclosing_function: enclName,
  };
}

/** Unused placeholder kept for typing symmetry with the data vocabulary. */
export const _unused: Record<string, never> = {};
void SERVER_ACCEPT_CONSTRUCTORS;

export function gather(source: string): GatheredFacts {
  const facts: HandshakeFact[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const visit = (node: ts.Node): void => {
    // Construction via `new WebSocketServer(...)` / `new Server(...)`
    if (ts.isNewExpression(node)) {
      const exprText = node.expression.getText(sf);
      if (exprText.endsWith("WebSocketServer") || exprText.endsWith(".Server")) {
        const kind: HandshakeAcceptKind = exprText.endsWith("WebSocketServer")
          ? "websocket-server"
          : "http-create-server";
        const encl = enclosingFunction(node);
        const scopeText = encl ? encl.getText(sf) : source;
        const timeoutPresent = containsTimeoutVocabulary(scopeText);
        const limitPresent = containsConnectionLimitVocabulary(scopeText);
        if (!timeoutPresent && !limitPresent) {
          facts.push({
            location: makeLocation(node, sf, source),
            accept_kind: kind,
            accept_expression: exprText,
            enclosing_function_text: scopeText,
            timeout_present: timeoutPresent,
            connection_limit_present: limitPresent,
          });
        }
      }
    }
    // Construction via call: http.createServer(...), net.createServer(...), server.listen(...), upgrade(...)
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);
      const kind = classifyAccept(exprText);
      if (kind) {
        const encl = enclosingFunction(node);
        const scopeText = encl ? encl.getText(sf) : source;
        const timeoutPresent = containsTimeoutVocabulary(scopeText);
        const limitPresent = containsConnectionLimitVocabulary(scopeText);
        if (!timeoutPresent && !limitPresent) {
          facts.push({
            location: makeLocation(node, sf, source),
            accept_kind: kind,
            accept_expression: exprText,
            enclosing_function_text: scopeText,
            timeout_present: timeoutPresent,
            connection_limit_present: limitPresent,
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}
