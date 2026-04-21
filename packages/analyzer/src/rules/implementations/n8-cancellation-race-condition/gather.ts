/**
 * N8 — Deterministic fact gathering for cancellation race.
 *
 * Walks the AST for cancel handlers. A cancel handler is either:
 *   (a) a function declaration/method whose name is in CANCEL_HANDLERS
 *   (b) an addEventListener('cancel'|'abort', fn)
 *   (c) a catch-clause catching AbortError or CancelledError
 * For each cancel handler, check whether the handler body contains a
 * mutation verb call AND the enclosing function text does not contain
 * transaction/lock vocabulary. If both hold, emit a fact.
 */

import ts from "typescript";
import {
  CANCEL_HANDLERS,
  ABORT_SIGNAL_NAMES,
  MUTATION_VERBS,
  TRANSACTION_VERBS,
  LOCK_VERBS,
} from "./data/cancellation-vocabulary.js";

export interface SourceLocation {
  readonly kind: "source_code_line";
  readonly line: number;
  readonly column: number;
  readonly snippet: string;
  readonly enclosing_function: string | null;
}

export type CancelHandlerKind =
  | "named-function"
  | "addEventListener-cancel"
  | "abortcontroller-signal"
  | "catch-abort-error";

export interface CancelRaceFact {
  readonly location: SourceLocation;
  readonly handler_kind: CancelHandlerKind;
  readonly mutation_verb: string;
  readonly enclosing_function_text: string;
  readonly transaction_present: boolean;
  readonly lock_present: boolean;
}

export interface GatheredFacts {
  readonly facts: CancelRaceFact[];
  readonly parse_succeeded: boolean;
}

function isCancelHandlerName(name: string): boolean {
  const lower = name.toLowerCase().replace(/[_-]/g, "");
  return Object.prototype.hasOwnProperty.call(CANCEL_HANDLERS, lower);
}

function isMutationCall(callText: string): string | null {
  const parts = callText.split(".");
  const last = parts[parts.length - 1].toLowerCase();
  if (Object.prototype.hasOwnProperty.call(MUTATION_VERBS, last)) return last;
  return null;
}

function tokenSet(text: string): Set<string> {
  const out = new Set<string>();
  let cur = "";
  for (const ch of text) {
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

function containsTransactionVocabulary(text: string): boolean {
  const tokens = tokenSet(text);
  for (const key of Object.keys(TRANSACTION_VERBS)) {
    if (tokens.has(key)) return true;
  }
  return false;
}

function containsLockVocabulary(text: string): boolean {
  const tokens = tokenSet(text);
  for (const key of Object.keys(LOCK_VERBS)) {
    if (tokens.has(key)) return true;
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
      ts.isMethodDeclaration(cur) ||
      ts.isClassDeclaration(cur)
    )
      return cur;
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

function findMutationInSubtree(root: ts.Node, sf: ts.SourceFile): string | null {
  let verb: string | null = null;
  const walk = (n: ts.Node): void => {
    if (verb) return;
    if (ts.isCallExpression(n)) {
      const text = n.expression.getText(sf);
      const m = isMutationCall(text);
      if (m) {
        verb = `${text}(...)`;
        return;
      }
    }
    ts.forEachChild(n, walk);
  };
  walk(root);
  return verb;
}

export function gather(source: string): GatheredFacts {
  const facts: CancelRaceFact[] = [];

  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);
  } catch {
    return { facts, parse_succeeded: false };
  }

  const emit = (node: ts.Node, handlerBody: ts.Node, kind: CancelHandlerKind): void => {
    const verb = findMutationInSubtree(handlerBody, sf);
    if (!verb) return;
    const encl = enclosingFunction(node);
    const scopeText = encl ? encl.getText(sf) : source;
    const txPresent = containsTransactionVocabulary(scopeText);
    const lockPresent = containsLockVocabulary(scopeText);
    if (txPresent || lockPresent) return;
    facts.push({
      location: makeLocation(node, sf, source),
      handler_kind: kind,
      mutation_verb: verb,
      enclosing_function_text: scopeText,
      transaction_present: txPresent,
      lock_present: lockPresent,
    });
  };

  const visit = (node: ts.Node): void => {
    // (a) Named cancel handler: function handleCancel() { ... delete(...) }
    if (ts.isFunctionDeclaration(node) && node.name && node.body) {
      const name = node.name.text;
      if (isCancelHandlerName(name)) emit(node, node.body, "named-function");
    }
    if (ts.isMethodDeclaration(node) && node.name && node.body) {
      const name = node.name.getText(sf);
      if (isCancelHandlerName(name)) emit(node, node.body, "named-function");
    }

    // (b) addEventListener('cancel'|'abort', fn) or signal.addEventListener(...)
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText(sf) === "addEventListener" &&
      node.arguments.length >= 2
    ) {
      const evArg = node.arguments[0];
      if (ts.isStringLiteral(evArg) && (evArg.text === "cancel" || evArg.text === "abort" || evArg.text === "cancelled" || evArg.text === "aborted")) {
        const handler = node.arguments[1];
        if (handler) emit(node, handler, "addEventListener-cancel");
      }
    }

    // (c) catch (err) where the identifier / type test suggests AbortError
    if (ts.isCatchClause(node) && node.block) {
      const catchText = node.getText(sf);
      if (
        catchText.includes("AbortError") ||
        catchText.includes("CancelledError") ||
        catchText.includes("aborted") ||
        catchText.includes("ABORT_ERR")
      ) {
        emit(node, node.block, "catch-abort-error");
      }
    }

    // Additionally: a call to .abort() on an AbortController followed by a mutation
    // in the same function — captured by presence of AbortSignal name + mutation.
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);
      const parts = exprText.split(".");
      const obj = parts[0];
      if (obj && Object.prototype.hasOwnProperty.call(ABORT_SIGNAL_NAMES, obj)) {
        // AbortController.abort() / signal.abort() — enclosing function must
        // also contain a mutation verb for the race to apply.
        const encl = enclosingFunction(node);
        if (encl) {
          const enclText = encl.getText(sf);
          const verb = findMutationInSubtree(encl, sf);
          if (verb) {
            const txPresent = containsTransactionVocabulary(enclText);
            const lockPresent = containsLockVocabulary(enclText);
            if (!txPresent && !lockPresent) {
              facts.push({
                location: makeLocation(node, sf, source),
                handler_kind: "abortcontroller-signal",
                mutation_verb: verb,
                enclosing_function_text: enclText,
                transaction_present: txPresent,
                lock_present: lockPresent,
              });
            }
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  };

  ts.forEachChild(sf, visit);
  return { facts, parse_succeeded: true };
}
