/**
 * O6 gather — AST detection of fingerprint-surface identifiers
 * appearing inside response-construction or thrown-Error payloads.
 *
 * Zero regex. Matches three structural shapes:
 *
 *   1. `res.json({...})` / `res.send(...)` / `reply.send(...)` with
 *      a fingerprint-surface identifier anywhere inside the argument
 *      subtree.
 *   2. `throw new Error({...})` / `throw err` where the message /
 *      payload contains a fingerprint-surface identifier.
 *   3. `return { error: err.stack, ... }` style return statements
 *      inside a catch block whose returned object includes a
 *      fingerprint-surface identifier.
 *
 * Sanitizer adjacency: if the enclosing function mentions any
 * `SANITIZER_HINTS` identifier, the site is demoted (has_sanitizer
 * flag set so the index.ts can skip or down-weight it).
 *
 * Auth-branch divergence: when a fingerprint site sits inside an
 * `if`-branch whose predicate reads an auth identifier
 * (req.user, req.isAuthenticated, authenticated, token, role),
 * the site is tagged auth_gated — so the finding can down-weight
 * (intended diagnostic behind auth) but not suppress (because
 * the opposite branch may still leak).
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PROCESS_SURFACE,
  PATH_SURFACE,
  OS_SURFACE,
  ERROR_FIELD_SURFACE,
  DB_SURFACE,
  DEPENDENCY_SURFACE,
  RESPONSE_EMITTERS,
  RESPONSE_METHODS,
  SANITIZER_HINTS,
} from "./data/fingerprint-surface.js";

const PROCESS_SET: ReadonlySet<string> = new Set(Object.keys(PROCESS_SURFACE));
const PATH_SET: ReadonlySet<string> = new Set(Object.keys(PATH_SURFACE));
const OS_SET: ReadonlySet<string> = new Set(Object.keys(OS_SURFACE));
const ERROR_FIELD_SET: ReadonlySet<string> = new Set(Object.keys(ERROR_FIELD_SURFACE));
const DB_SET: ReadonlySet<string> = new Set(Object.keys(DB_SURFACE));
const DEP_SET: ReadonlySet<string> = new Set(Object.keys(DEPENDENCY_SURFACE));
const EMITTER_SET: ReadonlySet<string> = new Set(Object.keys(RESPONSE_EMITTERS));
const METHOD_SET: ReadonlySet<string> = new Set(Object.keys(RESPONSE_METHODS));
const SANITIZER_SET: ReadonlySet<string> = new Set(Object.keys(SANITIZER_HINTS));

export type FingerprintKind =
  | "process"
  | "path"
  | "os"
  | "error-field"
  | "db"
  | "dependency";

export type ResponseShape =
  | "response-emitter-call"
  | "throw-error"
  | "catch-block-return";

export interface FingerprintSurfaceSite {
  kind: FingerprintKind;
  /** The identifier text that matched the surface catalogue. */
  surfaceToken: string;
  /** Shape of the response construction. */
  responseShape: ResponseShape;
  /** Verbatim observed expression (truncated to 200 chars). */
  observed: string;
  /** Source-kind Location of the offending node. */
  location: Location;
  /** Enclosing function location (null for top-level). */
  enclosingFunctionLocation: Location | null;
  /** Enclosing function has a sanitiser identifier in scope. */
  hasSanitizer: boolean;
  /** Matched sanitiser identifier, or null. */
  matchedSanitizer: string | null;
  /** Site sits inside an auth-gated branch. */
  authGated: boolean;
}

export interface O6Gathered {
  sites: FingerprintSurfaceSite[];
  hasResponseSurface: boolean;
}

export function gatherO6(context: AnalysisContext): O6Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], hasResponseSurface: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  let hasResponseSurface = false;
  const sites: FingerprintSurfaceSite[] = [];

  ts.forEachChild(sf, function visit(node) {
    // Shape 1 & 3: response emitter or return inside catch
    if (ts.isCallExpression(node)) {
      const emitted = classifyResponseEmit(node);
      if (emitted) {
        hasResponseSurface = true;
        collectFingerprintSites(
          emitted.payloadArg,
          node,
          sf,
          "response-emitter-call",
          sites,
        );
      }
    }
    if (ts.isReturnStatement(node)) {
      if (node.expression && insideCatchClause(node)) {
        hasResponseSurface = true;
        collectFingerprintSites(
          node.expression,
          node,
          sf,
          "catch-block-return",
          sites,
        );
      }
    }
    // Shape 2: throw new Error({...}) / throw obj
    if (ts.isThrowStatement(node) && node.expression) {
      collectFingerprintSites(
        node.expression,
        node,
        sf,
        "throw-error",
        sites,
      );
    }
    ts.forEachChild(node, visit);
  });

  return { sites, hasResponseSurface };
}

/**
 * If `call` is a response-emitter invocation (res.json / res.send /
 * reply.send / ctx.body = / result = ...), returns its payload
 * argument node.
 */
function classifyResponseEmit(
  call: ts.CallExpression,
): { payloadArg: ts.Expression } | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text.toLowerCase();
  if (!METHOD_SET.has(method)) return null;
  const recv = call.expression.expression;
  // res.json(...) — receiver is an identifier in EMITTER_SET.
  if (ts.isIdentifier(recv) && EMITTER_SET.has(recv.text)) {
    const arg = call.arguments[0];
    if (arg) return { payloadArg: arg };
  }
  // res.status(500).json(...) — walk one level of chained PropertyAccess.
  if (ts.isCallExpression(recv) && ts.isPropertyAccessExpression(recv.expression)) {
    const inner = recv.expression.expression;
    if (ts.isIdentifier(inner) && EMITTER_SET.has(inner.text)) {
      const arg = call.arguments[0];
      if (arg) return { payloadArg: arg };
    }
  }
  return null;
}

function collectFingerprintSites(
  root: ts.Node,
  enclosingNode: ts.Node,
  sf: ts.SourceFile,
  shape: ResponseShape,
  out: FingerprintSurfaceSite[],
): void {
  const hits: Array<{ kind: FingerprintKind; token: string; node: ts.Node }> = [];
  walkForFingerprintIdentifiers(root, hits);
  if (hits.length === 0) return;
  const enclosing = findEnclosingFunction(enclosingNode);
  const enclosingLoc = enclosing ? sourceLocation(sf, enclosing) : null;
  const sanitizer = enclosing ? findSanitizerInScope(enclosing) : null;
  const authGated = isAuthGatedBranch(enclosingNode);
  for (const hit of hits) {
    out.push({
      kind: hit.kind,
      surfaceToken: hit.token,
      responseShape: shape,
      observed: truncateText(hit.node.getText(sf), 200),
      location: sourceLocation(sf, hit.node),
      enclosingFunctionLocation: enclosingLoc,
      hasSanitizer: sanitizer !== null,
      matchedSanitizer: sanitizer,
      authGated,
    });
  }
}

function walkForFingerprintIdentifiers(
  root: ts.Node,
  out: Array<{ kind: FingerprintKind; token: string; node: ts.Node }>,
): void {
  function visit(n: ts.Node): void {
    if (ts.isPropertyAccessExpression(n)) {
      const name = n.name.text;
      const classified = classifyFingerprintToken(name);
      if (classified !== null) {
        out.push({ kind: classified, token: name, node: n });
      }
    } else if (ts.isIdentifier(n)) {
      const classified = classifyFingerprintToken(n.text);
      // Only flag bare identifiers for the path surface (__dirname /
      // __filename) — the rest require a property-access context to
      // avoid firing on parameter names that happen to equal
      // "version" or "stack".
      if (classified === "path") {
        out.push({ kind: classified, token: n.text, node: n });
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(root);
}

function classifyFingerprintToken(token: string): FingerprintKind | null {
  if (PROCESS_SET.has(token)) return "process";
  if (PATH_SET.has(token)) return "path";
  if (OS_SET.has(token)) return "os";
  if (ERROR_FIELD_SET.has(token)) return "error-field";
  if (DB_SET.has(token)) return "db";
  if (DEP_SET.has(token)) return "dependency";
  return null;
}

function findSanitizerInScope(enclosing: ts.Node): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && SANITIZER_SET.has(n.text)) {
      found = n.text;
      return;
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(enclosing, visit);
  return found;
}

function isAuthGatedBranch(node: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isIfStatement(cur)) {
      const pred = cur.expression.getText();
      const lowered = pred.toLowerCase();
      if (
        lowered.includes("authenticated") ||
        lowered.includes("req.user") ||
        lowered.includes("session") ||
        lowered.includes("token") ||
        lowered.includes("role")
      ) {
        return true;
      }
    }
    cur = cur.parent;
  }
  return false;
}

function insideCatchClause(node: ts.Node): boolean {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isCatchClause(cur)) return true;
    cur = cur.parent;
  }
  return false;
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

function truncateText(s: string, max: number): string {
  if (s.length <= max) return s;
  return s.slice(0, max) + "…";
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
