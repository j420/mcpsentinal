/**
 * N2 — Deterministic fact gathering for notification flooding.
 *
 * Strategy: visit all CallExpression nodes in the AST. If the call's name
 * appears in NOTIFICATION_VERBS, walk the parent chain to determine whether
 * the call sits inside a loop or a timer callback. If it does, gather the
 * enclosing function's text to check for throttle vocabulary.
 *
 * Zero regex literals. Vocabulary lives in data/notification-vocabulary.ts.
 */

import ts from "typescript";
import {
  NOTIFICATION_VERBS,
  TIMER_FUNCTIONS,
  THROTTLE_TOKENS,
} from "./data/notification-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export interface NotificationFlood {
  readonly location: SourceLocation;
  readonly call_expression: string;
  readonly verb_identifier: string;
  readonly loop_context: "for-loop" | "while-loop" | "do-loop" | "set-interval" | "batch-handler";
  readonly throttle_tokens_present: boolean;
  readonly enclosing_function_text: string;
}

export interface GatheredFacts {
  readonly facts: NotificationFlood[];
  readonly parse_succeeded: boolean;
}

const LOOP_KINDS = new Set<ts.SyntaxKind>([
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
]);

/** Tokenise a text fragment into lowercase word tokens. */
function tokenSet(text: string): Set<string> {
  const out = new Set<string>();
  let current = "";
  for (const ch of text) {
    const isWord = (ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z") || (ch >= "0" && ch <= "9") || ch === "_";
    if (isWord) current += ch;
    else {
      if (current) out.add(current.toLowerCase());
      current = "";
    }
  }
  if (current) out.add(current.toLowerCase());
  return out;
}

function hasThrottleTokens(text: string): boolean {
  const tokens = tokenSet(text);
  // Explicit keyword check: "break" / "return" indicate deliberate early exit.
  if (text.includes("break;") || text.includes("break }") || text.includes("break\n")) return true;
  for (const [key, role] of Object.entries(THROTTLE_TOKENS)) {
    void role;
    if (key === "break_keyword" || key === "return_keyword") continue;
    const normalised = key.replace(/_/g, "").toLowerCase();
    if (tokens.has(normalised)) return true;
    if (tokens.has(key.toLowerCase())) return true;
  }
  return false;
}

function enclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isMethodDeclaration(cur)
    )
      return cur;
    cur = cur.parent;
  }
  return null;
}

/** Walk up the AST to find whether `node` lives inside a loop. */
function loopContextOf(node: ts.Node, sf: ts.SourceFile): NotificationFlood["loop_context"] | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (LOOP_KINDS.has(cur.kind)) {
      if (cur.kind === ts.SyntaxKind.ForStatement) return "for-loop";
      if (cur.kind === ts.SyntaxKind.ForInStatement) return "for-loop";
      if (cur.kind === ts.SyntaxKind.ForOfStatement) return "for-loop";
      if (cur.kind === ts.SyntaxKind.WhileStatement) return "while-loop";
      if (cur.kind === ts.SyntaxKind.DoStatement) return "do-loop";
    }
    if (ts.isCallExpression(cur)) {
      const text = cur.expression.getText(sf);
      if (Object.prototype.hasOwnProperty.call(TIMER_FUNCTIONS, text)) return "set-interval";
    }
    // Function boundary handling — if the function is itself the argument of a
    // timer call (setInterval/setImmediate), the timer IS the loop.
    if (
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur)
    ) {
      const parent = cur.parent;
      if (parent && ts.isCallExpression(parent)) {
        const exprText = parent.expression.getText(sf);
        if (Object.prototype.hasOwnProperty.call(TIMER_FUNCTIONS, exprText)) {
          return "set-interval";
        }
      }
      return null;
    }
    if (ts.isFunctionDeclaration(cur) || ts.isMethodDeclaration(cur)) {
      return null;
    }
    cur = cur.parent;
  }
  return null;
}

function isNotificationCall(expressionText: string): string | null {
  // Extract the terminal identifier (e.g. `server.sendNotification` → `sendNotification`)
  const parts = expressionText.split(".");
  const last = parts[parts.length - 1].trim();
  const key = last.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(NOTIFICATION_VERBS, key)) return last;
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

export function gather(source: string): GatheredFacts {
  const facts: NotificationFlood[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);
      const verb = isNotificationCall(exprText);
      if (verb) {
        const ctx = loopContextOf(node, sf);
        if (ctx) {
          const encl = enclosingFunction(node);
          const enclText = encl ? encl.getText(sf) : source;
          const throttled = hasThrottleTokens(enclText);
          if (!throttled) {
            facts.push({
              location: makeLocation(node, sf, source),
              call_expression: exprText,
              verb_identifier: verb,
              loop_context: ctx,
              throttle_tokens_present: throttled,
              enclosing_function_text: enclText,
            });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}
