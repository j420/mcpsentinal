/**
 * C8 — No Auth on Network Interface: AST-driven fact gathering.
 *
 * Walks the TS compiler AST for `<x>.listen(port[, host])` and
 * `<x>.bind(host)` calls. For each bind whose host is "0.0.0.0" / "::" /
 * unspecified (defaults to 0.0.0.0 on most stacks), checks whether the
 * surrounding source contains an `<x>.use(<auth>)` call where <auth>
 * is a Call/Identifier whose name appears in AUTH_MIDDLEWARE_TOKENS.
 *
 * The search for auth is conservative: present-but-unwired imports
 * do not count. The check looks for actual `use()` calls or
 * route-level `passport.authenticate()` style middleware.
 *
 * Also handles Python `uvicorn.run(app, host="0.0.0.0", ...)` via line
 * scan.
 *
 * Zero regex literals.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  LISTEN_METHODS,
  AUTH_MIDDLEWARE_TOKENS,
  ALL_INTERFACE_HOSTS,
  LOOPBACK_HOSTS,
  PYTHON_AUTH_MARKERS,
} from "./data/config.js";

export type C8LeakKind =
  | "listen-explicit-wildcard-host"
  | "listen-default-host-no-auth"
  | "python-uvicorn-wildcard";

export interface NetworkBindFact {
  readonly kind: C8LeakKind;
  readonly location: Location;
  readonly observed: string;
  /** Whether ANY auth middleware use() was discovered in the source. */
  readonly authMiddlewarePresent: boolean;
}

export interface C8GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly NetworkBindFact[];
}

const SYNTHETIC_FILE = "<source>";
const TEST_FILE_RUNNER_MARKERS: readonly string[] = [
  'from "vitest"',
  "from 'vitest'",
  'from "@jest/globals"',
  "from '@jest/globals'",
  "import pytest",
];
const TEST_FILE_SUITE_MARKERS: readonly string[] = [
  "\ndescribe(",
  "\nit(",
  "\ntest(",
];

export function gatherC8(context: AnalysisContext): C8GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (looksLikeTestFile(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const file = SYNTHETIC_FILE;
  const facts: NetworkBindFact[] = [];

  if (looksLikePython(source)) {
    collectPython(source, file, facts);
  } else {
    try {
      const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true);
      const authPresent = sourceContainsAuthMiddlewareCall(sf);
      ts.forEachChild(sf, function visit(node) {
        if (ts.isCallExpression(node)) {
          inspectListen(node, sf, file, facts, authPresent);
        }
        ts.forEachChild(node, visit);
      });
    } catch {
      // Parse failure: nothing to emit.
    }
  }

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file,
    facts,
  };
}

function inspectListen(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  facts: NetworkBindFact[],
  authPresent: boolean,
): void {
  const callee = call.expression;
  if (!ts.isPropertyAccessExpression(callee)) return;
  if (!LISTEN_METHODS.has(callee.name.text)) return;
  if (call.arguments.length === 0) return;

  // The host argument can be at index 1 (after port) or index 0 (for `bind`).
  let hostArg: ts.Expression | null = null;
  if (callee.name.text === "bind") {
    hostArg = call.arguments[0];
  } else if (call.arguments.length >= 2) {
    hostArg = call.arguments[1];
  }

  let kind: C8LeakKind | null = null;

  if (hostArg && ts.isStringLiteral(hostArg)) {
    if (LOOPBACK_HOSTS.has(hostArg.text)) {
      // Loopback bind — never a leak.
      return;
    }
    if (ALL_INTERFACE_HOSTS.has(hostArg.text)) {
      kind = "listen-explicit-wildcard-host";
    } else {
      // Specific external IP — not a wildcard but still public; flag if no auth.
      if (!authPresent) kind = "listen-explicit-wildcard-host";
    }
  } else if (hostArg === null) {
    // Bare listen(port) — defaults to 0.0.0.0
    kind = "listen-default-host-no-auth";
  }

  if (kind === null) return;
  if (authPresent) return; // No leak when an auth middleware is wired.

  facts.push({
    kind,
    location: locationOf(callee, sf, file),
    observed: truncate(call.getText(sf), 160),
    authMiddlewarePresent: authPresent,
  });
}

function sourceContainsAuthMiddlewareCall(sf: ts.SourceFile): boolean {
  let found = false;
  ts.forEachChild(sf, function visit(node) {
    if (found) return;
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      if (method === "use" || method === "register" || method === "addMiddleware") {
        for (const arg of node.arguments) {
          if (referencesAuthToken(arg)) {
            found = true;
            return;
          }
        }
      }
      // Per-route middleware: app.post("/x", authMiddleware, handler)
      if (
        ts.isIdentifier(node.expression.expression) ||
        node.expression.name.text === "post" ||
        node.expression.name.text === "get" ||
        node.expression.name.text === "put" ||
        node.expression.name.text === "delete"
      ) {
        for (const arg of node.arguments) {
          if (referencesAuthToken(arg)) {
            found = true;
            return;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  });
  return found;
}

function referencesAuthToken(node: ts.Node): boolean {
  if (ts.isIdentifier(node) && matchesAuthToken(node.text)) return true;
  if (ts.isCallExpression(node)) {
    const callee = node.expression;
    if (ts.isIdentifier(callee) && matchesAuthToken(callee.text)) return true;
    if (ts.isPropertyAccessExpression(callee)) {
      // passport.authenticate(...)
      if (ts.isIdentifier(callee.expression) && matchesAuthToken(callee.expression.text)) return true;
      if (matchesAuthToken(callee.name.text)) return true;
    }
  }
  if (ts.isPropertyAccessExpression(node)) {
    if (ts.isIdentifier(node.expression) && matchesAuthToken(node.expression.text)) return true;
    if (matchesAuthToken(node.name.text)) return true;
  }
  return false;
}

function matchesAuthToken(name: string): boolean {
  if (AUTH_MIDDLEWARE_TOKENS.has(name)) return true;
  const lower = name.toLowerCase();
  if (AUTH_MIDDLEWARE_TOKENS.has(lower)) return true;
  // Allow names containing common auth substrings (cheap, conservative).
  return lower.includes("auth") || lower.includes("jwt") || lower.includes("bearer") || lower.includes("apikey");
}

function collectPython(text: string, file: string, facts: NetworkBindFact[]): void {
  const lines = text.split("\n");
  // Whole-source auth marker check.
  const authPresent = pythonContainsAuthMarker(text);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.includes("uvicorn.run") && !raw.includes("hypercorn.run")) continue;
    // Find host="0.0.0.0" or default (no host kwarg).
    const hasWildcard = raw.includes('host="0.0.0.0"') || raw.includes("host='0.0.0.0'") || raw.includes('host="::"');
    const hasLoopback = raw.includes('host="127.0.0.1"') || raw.includes("host='127.0.0.1'") || raw.includes('host="localhost"');
    if (hasLoopback) continue;
    // Default host on uvicorn.run is 127.0.0.1, but most production deploys add host="0.0.0.0" explicitly.
    if (!hasWildcard) continue;
    if (authPresent) continue;
    const idx = raw.indexOf("uvicorn") >= 0 ? raw.indexOf("uvicorn") : raw.indexOf("hypercorn");
    facts.push({
      kind: "python-uvicorn-wildcard",
      location: { kind: "source", file, line: i + 1, col: idx + 1 },
      observed: truncate(raw.trim(), 160),
      authMiddlewarePresent: false,
    });
  }
}

function pythonContainsAuthMarker(text: string): boolean {
  for (const m of PYTHON_AUTH_MARKERS) {
    if (text.includes(m)) return true;
  }
  return false;
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function locationOf(node: ts.Node, sf: ts.SourceFile, file: string): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function looksLikeTestFile(source: string): boolean {
  const hasRunner = TEST_FILE_RUNNER_MARKERS.some((m) => source.includes(m));
  const hasSuite =
    TEST_FILE_SUITE_MARKERS.some((m) => source.includes(m)) ||
    source.startsWith("describe(") ||
    source.startsWith("it(") ||
    source.startsWith("test(");
  return hasRunner && hasSuite;
}

function looksLikePython(text: string): boolean {
  const hasDef = text.includes("\ndef ") || text.startsWith("def ");
  const hasJsKeywords =
    text.includes("const ") || text.includes("let ") || text.includes("function ");
  return hasDef && !hasJsKeywords;
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}
