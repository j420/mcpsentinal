/**
 * K13 gather — unsanitized tool output.
 *
 * Fires when a tool handler's response value (ReturnStatement body or
 * response-call argument) is derived from an external source (network
 * fetch, file read, db query, or an external-content-shaped handler
 * parameter) without a sanitizer applied to the RETURNED identifier.
 *
 * Zero regex. All vocabulary lives in `./data/taint-vocabulary.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  EXTERNAL_SOURCE_IDENTIFIER_TOKENS,
  EXTERNAL_SOURCE_METHODS,
  EXTERNAL_PARAM_NAME_TOKENS,
  SANITIZER_CALL_IDENTIFIERS,
  SANITIZER_RECEIVER_METHODS,
  RESPONSE_RECEIVERS,
  RESPONSE_METHODS,
  TEST_RUNNER_MODULES,
  TEST_RUNNER_TOPLEVEL,
} from "./data/taint-vocabulary.js";

// ─── Vocabulary sets ───────────────────────────────────────────────────────

const EXT_ID_TOKENS: ReadonlySet<string> = new Set(
  Object.keys(EXTERNAL_SOURCE_IDENTIFIER_TOKENS),
);
const EXT_METHOD_MAP: ReadonlyMap<string, string> = new Map(
  Object.entries(EXTERNAL_SOURCE_METHODS),
);
const EXT_PARAM_TOKENS: ReadonlySet<string> = new Set(
  Object.keys(EXTERNAL_PARAM_NAME_TOKENS),
);
const SANITIZER_CALL_SET: ReadonlySet<string> = new Set(
  Object.keys(SANITIZER_CALL_IDENTIFIERS),
);
const RESPONSE_RECEIVER_SET: ReadonlySet<string> = new Set(
  Object.keys(RESPONSE_RECEIVERS),
);
const RESPONSE_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(RESPONSE_METHODS),
);
const TEST_MODULE_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_MODULES));
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_TOPLEVEL));

// ─── Public types ──────────────────────────────────────────────────────────

export type SourceKind =
  | "network-fetch"
  | "file-read"
  | "db-query"
  | "external-scrape"
  | "handler-param";

export type ResponseSiteType = "return-statement" | "response-call";

export interface ExternalSource {
  kind: SourceKind;
  location: Location;           // where the external read happens
  identifier: string | null;    // bound variable name, if any, that holds the tainted value
  observed: string;             // snippet <200 chars
}

export interface UnsanitizedFlow {
  source: ExternalSource;
  responseLocation: Location;   // return-statement / response-call location
  siteType: ResponseSiteType;
  sanitizerApplied: {
    present: boolean;
    sameVariable: boolean;
    detail: string;
  };
  enclosingFunctionLocation: Location | null;
}

export interface FileEvidence {
  file: string;
  isTestFile: boolean;
  flows: UnsanitizedFlow[];
}

export interface K13Gathered {
  perFile: FileEvidence[];
}

// ─── Entry ─────────────────────────────────────────────────────────────────

export function gatherK13(context: AnalysisContext): K13Gathered {
  const files = collectSourceFiles(context);
  const perFile: FileEvidence[] = [];
  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }
  return { perFile };
}

function collectSourceFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) {
    out.set("<concatenated-source>", context.source_code);
  }
  return out;
}

function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  const flows: UnsanitizedFlow[] = [];

  if (!isTestFile) {
    // Visit every function body — that's where tool handlers live.
    ts.forEachChild(sf, function visit(node) {
      if (isFunctionLike(node)) {
        analyzeFunction(node, sf, file, flows);
      }
      ts.forEachChild(node, visit);
    });
  }

  return { file, isTestFile, flows };
}

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let topLevelItOrTest = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_MODULE_SET.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee) && TEST_TOPLEVEL_SET.has(callee.text)) {
        for (const arg of stmt.expression.arguments) {
          if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
            topLevelRunnerCalls++;
            if (callee.text === "it" || callee.text === "test") topLevelItOrTest++;
            break;
          }
        }
      }
    }
  }
  if (topLevelItOrTest > 0) return true;
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
}

type FunctionLike =
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration;

function isFunctionLike(node: ts.Node): node is FunctionLike {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node)
  );
}

// ─── Per-function analysis ─────────────────────────────────────────────────

function analyzeFunction(
  fn: FunctionLike,
  sf: ts.SourceFile,
  file: string,
  flows: UnsanitizedFlow[],
): void {
  const fnLoc = sourceLocation(sf, file, fn);
  const body: ts.ConciseBody | undefined = fn.body;
  if (!body) return;
  // Narrowed alias for TypeScript's type-flow analysis through closures.
  const bodyNode: ts.Node = body;

  // Pass 1: collect external sources declared INSIDE the function body.
  //   const x = await fetch(url) → x is tainted with kind=network-fetch
  //   const y = readFileSync(p)  → y is tainted with kind=file-read
  // Pass 1b: add tainted handler parameters whose names imply external content.
  const taintedVars = new Map<string, ExternalSource>();

  // Tainted parameters
  for (const p of fn.parameters) {
    if (!ts.isIdentifier(p.name)) continue;
    if (paramNameImpliesExternalContent(p.name.text)) {
      taintedVars.set(p.name.text, {
        kind: "handler-param",
        location: sourceLocation(sf, file, p),
        identifier: p.name.text,
        observed: `handler parameter \`${p.name.text}\``.slice(0, 200),
      });
    }
  }

  // Tainted locals — scan the body for `const x = <external source call>`
  // OR `const x = <expression referencing an already-tainted identifier>`.
  // The second clause propagates taint through chained operations like
  // `const html = await page.text()` where `page` is already tainted.
  //
  // K13 scope discipline: taint propagation is RESTRICTED to text-shaped
  // outputs (a body / page / HTML / raw bytes), NOT to structured JSON
  // or parsed objects. If the initializer is a call to a structure-
  // extracting method (`.json()`, `.rows`, `.data`), the binding is
  // treated as structured — it cannot carry arbitrary injection into
  // the AI's textual context without being serialised, which is a
  // different layer's problem.
  //
  // Taint-cleansing: if the initializer is a direct call to a sanitizer
  // function (bare or receiver.method) with a tainted argument, the
  // binding is NOT tainted — the sanitizer explicitly cleanses.
  //
  // We iterate to a fixed point because a later statement may expand the
  // tainted set and a subsequent declaration may reference it.
  let changed = true;
  while (changed) {
    changed = false;
    function scanVars(n: ts.Node): void {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        const name = n.name.text;
        if (taintedVars.has(name)) {
          ts.forEachChild(n, scanVars);
          return;
        }
        // Sanitizer-cleansed binding — skip taint propagation.
        if (initializerIsSanitizerCall(n.initializer)) {
          ts.forEachChild(n, scanVars);
          return;
        }
        // Structure-extracting binding — NOT tainted as a text flow.
        if (initializerExtractsStructure(n.initializer)) {
          ts.forEachChild(n, scanVars);
          return;
        }
        const direct = classifyExpressionAsExternalSource(n.initializer, sf, file);
        if (direct !== null) {
          taintedVars.set(name, { ...direct, identifier: name });
          changed = true;
        } else {
          // Taint propagation via identifier reference — only if the
          // initializer produces a text-shaped value (or references the
          // tainted var directly, e.g. `const x = tainted`).
          if (!initializerProducesText(n.initializer, taintedVars)) {
            ts.forEachChild(n, scanVars);
            return;
          }
          const originSrc = findTaintedInitializerSource(n.initializer, taintedVars);
          if (originSrc !== null) {
            taintedVars.set(name, {
              ...originSrc,
              location: sourceLocation(sf, file, n),
              identifier: name,
              observed: lineTextAt(sf, n.getStart(sf)).trim().slice(0, 200),
            });
            changed = true;
          }
        }
      }
      ts.forEachChild(n, scanVars);
    }
    scanVars(bodyNode);
  }

  // Pass 2: walk response emission sites. For each, trace whether it uses
  // a tainted identifier / contains a tainted sub-expression, and whether a
  // sanitizer is applied to the SAME identifier.
  function scanResponse(n: ts.Node): void {
    // ReturnStatement
    if (ts.isReturnStatement(n) && n.expression) {
      maybeRecord(n.expression, "return-statement", n);
    }
    // Response call (res.send(...))
    if (ts.isCallExpression(n) && isResponseCall(n)) {
      for (const arg of n.arguments) {
        maybeRecord(arg, "response-call", n);
      }
    }
    ts.forEachChild(n, scanResponse);
  }
  scanResponse(bodyNode);

  function maybeRecord(
    expr: ts.Expression,
    siteType: ResponseSiteType,
    anchor: ts.Node,
  ): void {
    // Scope: K13 only cares about text-shaped tool output. If the response
    // expression is itself a structure-extractor (`resp.json()`, `x.rows`,
    // `JSON.parse(...)`), the AI client receives parsed structure, not
    // injection-carrying text. Skip.
    if (responseExpressionIsStructured(expr)) return;

    // Two conditions: (1) an external source flows into the expression,
    // OR a tainted identifier is used.
    const inlineSource = findExternalSourceInExpression(expr, sf, file);
    let source: ExternalSource | null = inlineSource;
    let returnedIdentifier: string | null = null;

    // If any descendant identifier is a known tainted var, record it.
    const tainted = findTaintedDescendantIdentifier(expr, taintedVars);
    if (tainted) {
      returnedIdentifier = tainted;
      if (!source) {
        source = taintedVars.get(tainted) ?? null;
      }
    }
    if (!source) return;

    // Check whether the enclosing function body contains a sanitizer call
    // whose argument is the same identifier as returnedIdentifier (or the
    // source identifier itself if the response is the raw expression).
    const sanitizerTarget =
      returnedIdentifier ?? source.identifier ?? null;
    const sanitizer = sanitizerAppliedTo(bodyNode, sanitizerTarget);

    flows.push({
      source,
      responseLocation: sourceLocation(sf, file, anchor),
      siteType,
      sanitizerApplied: sanitizer,
      enclosingFunctionLocation: fnLoc,
    });
  }
}

// ─── External-source classification ────────────────────────────────────────

function classifyExpressionAsExternalSource(
  expr: ts.Expression,
  sf: ts.SourceFile,
  file: string,
): ExternalSource | null {
  // await X → unwrap
  const bare = unwrapAwait(expr);
  // CallExpression
  if (ts.isCallExpression(bare)) {
    const kind = classifyCalleeAsExternalKind(bare);
    if (kind !== null) {
      return {
        kind,
        location: sourceLocation(sf, file, bare),
        identifier: null,
        observed: lineTextAt(sf, bare.getStart(sf)).trim().slice(0, 200),
      };
    }
  }
  // PropertyAccess chain over an await on an external call
  if (ts.isPropertyAccessExpression(bare)) {
    // Recurse into the "expression" part (e.g. (await fetch(x)).text)
    const inner = classifyExpressionAsExternalSource(bare.expression as ts.Expression, sf, file);
    if (inner) return { ...inner, location: sourceLocation(sf, file, bare) };
  }
  return null;
}

function unwrapAwait(expr: ts.Expression): ts.Expression {
  let cur: ts.Expression = expr;
  while (ts.isAwaitExpression(cur) || ts.isParenthesizedExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

/** Classify a CallExpression's callee into an external-source kind, or null. */
function classifyCalleeAsExternalKind(call: ts.CallExpression): SourceKind | null {
  // Bare identifier: fetch(x) / readFile(p) / request(url)
  if (ts.isIdentifier(call.expression)) {
    const id = call.expression.text.toLowerCase();
    for (const token of EXT_ID_TOKENS) {
      if (id.includes(token)) {
        return classifyBySubstring(token);
      }
    }
    return null;
  }
  // receiver.method: axios.get / fs.readFile / db.query
  if (ts.isPropertyAccessExpression(call.expression)) {
    const method = call.expression.name.text.toLowerCase();
    const mapped = EXT_METHOD_MAP.get(method);
    if (mapped) {
      return mapped as SourceKind;
    }
  }
  return null;
}

function classifyBySubstring(token: string): SourceKind {
  if (token === "readfile" || token === "readfilesync" || token === "readstream") return "file-read";
  if (token === "query" || token === "find" || token === "findone" || token === "findall") return "db-query";
  if (token === "scrape" || token === "crawl") return "external-scrape";
  return "network-fetch";
}

/**
 * Walk the response expression looking for ANY external-source-shaped
 * CallExpression descendant. Used when the response is the raw expression
 * (no intermediate variable), e.g. `return (await fetch(url)).text();`.
 */
function findExternalSourceInExpression(
  expr: ts.Expression,
  sf: ts.SourceFile,
  file: string,
): ExternalSource | null {
  let found: ExternalSource | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isCallExpression(n)) {
      const kind = classifyCalleeAsExternalKind(n);
      if (kind) {
        found = {
          kind,
          location: sourceLocation(sf, file, n),
          identifier: null,
          observed: lineTextAt(sf, n.getStart(sf)).trim().slice(0, 200),
        };
        return;
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

/**
 * If any descendant Identifier in `expr` matches a tainted variable, return
 * that variable's ExternalSource record. Used to propagate taint through
 * chained expressions like `await page.text()` where `page` is tainted.
 */
function findTaintedInitializerSource(
  expr: ts.Expression,
  taintedVars: Map<string, ExternalSource>,
): ExternalSource | null {
  let found: ExternalSource | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n)) {
      const src = taintedVars.get(n.text);
      if (src) {
        found = src;
        return;
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

function findTaintedDescendantIdentifier(
  expr: ts.Expression,
  taintedVars: Map<string, ExternalSource>,
): string | null {
  if (ts.isIdentifier(expr) && taintedVars.has(expr.text)) return expr.text;
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && taintedVars.has(n.text)) {
      found = n.text;
      return;
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

/**
 * True if the response expression is structurally parsed — the AI client
 * receives a JS object tree, not a text blob. Calls like `resp.json()`,
 * `result.rows`, `JSON.parse(x)` fall here and are out of K13 scope.
 */
function responseExpressionIsStructured(expr: ts.Expression): boolean {
  const bare = unwrapAwait(expr);
  // Call to a structural extractor: x.json(), x.toJSON(), JSON.parse(x)
  if (ts.isCallExpression(bare) && ts.isPropertyAccessExpression(bare.expression)) {
    const m = bare.expression.name.text.toLowerCase();
    if (m === "json" || m === "tojson") return true;
    if (ts.isIdentifier(bare.expression.expression)) {
      const r = bare.expression.expression.text.toLowerCase();
      if (r === "json" && m === "parse") return true;
    }
  }
  // PropertyAccess to a structural field: x.rows, x.data, x.results
  if (ts.isPropertyAccessExpression(bare)) {
    const field = bare.name.text.toLowerCase();
    if (field === "rows" || field === "results") return true;
  }
  return false;
}

/**
 * True if the initializer extracts structured data from a tainted value
 * (`.json()`, `.rows`, `.data`, `.body` when it's an object, etc.). These
 * bindings carry parsed structure, not raw text, and are out of K13 scope.
 */
function initializerExtractsStructure(expr: ts.Expression): boolean {
  const bare = unwrapAwait(expr);
  // PropertyAccess to a structural field: x.rows, x.data
  if (ts.isPropertyAccessExpression(bare)) {
    const field = bare.name.text.toLowerCase();
    if (field === "rows" || field === "data" || field === "json" || field === "result" || field === "results") {
      return true;
    }
  }
  // Call to a structural extractor: x.json(), JSON.parse(x)
  if (ts.isCallExpression(bare)) {
    if (ts.isPropertyAccessExpression(bare.expression)) {
      const m = bare.expression.name.text.toLowerCase();
      if (m === "json" || m === "tojson") return true;
    }
    if (ts.isPropertyAccessExpression(bare.expression) && ts.isIdentifier(bare.expression.expression)) {
      const r = bare.expression.expression.text.toLowerCase();
      const m = bare.expression.name.text.toLowerCase();
      if (r === "json" && m === "parse") return true;
    }
  }
  return false;
}

/**
 * True if the initializer produces a text-shaped value — a `.text()` /
 * `.buffer()` / `.arrayBuffer()` call, a template literal, a string
 * concatenation, or a direct reference to a tainted variable.
 *
 * Used to gate taint propagation: only text-shaped downstream values
 * carry injection risk to the AI client.
 */
function initializerProducesText(
  expr: ts.Expression,
  taintedVars: Map<string, ExternalSource>,
): boolean {
  const bare = unwrapAwait(expr);
  // Direct Identifier reference → text shape comes from upstream
  if (ts.isIdentifier(bare)) return taintedVars.has(bare.text);
  // Template literal → text
  if (ts.isTemplateExpression(bare) || ts.isNoSubstitutionTemplateLiteral(bare)) return true;
  // String concatenation
  if (ts.isBinaryExpression(bare) && bare.operatorToken.kind === ts.SyntaxKind.PlusToken) return true;
  // Call to .text() / .buffer() / .arrayBuffer() / .toString() on tainted
  if (ts.isCallExpression(bare) && ts.isPropertyAccessExpression(bare.expression)) {
    const m = bare.expression.name.text.toLowerCase();
    if (m === "text" || m === "buffer" || m === "arraybuffer" || m === "tostring" || m === "read") {
      // The receiver must be tainted; otherwise this is neutral
      const inner = bare.expression.expression;
      if (ts.isIdentifier(inner) && taintedVars.has(inner.text)) return true;
    }
  }
  // Member access to a string-shaped field of a tainted value: x.html, x.body, x.text, x.content
  if (ts.isPropertyAccessExpression(bare)) {
    const field = bare.name.text.toLowerCase();
    if (field === "html" || field === "body" || field === "text" || field === "content" || field === "value" || field === "raw") {
      const inner = bare.expression;
      if (ts.isIdentifier(inner) && taintedVars.has(inner.text)) return true;
    }
  }
  return false;
}

/**
 * True if the initializer is a direct call to a sanitizer function.
 * `unwrapAwait` handles `await sanitize(x)` / `await DOMPurify.sanitize(x)`.
 */
function initializerIsSanitizerCall(expr: ts.Expression): boolean {
  const bare = unwrapAwait(expr);
  if (!ts.isCallExpression(bare)) return false;
  if (ts.isIdentifier(bare.expression)) {
    return SANITIZER_CALL_SET.has(bare.expression.text.toLowerCase());
  }
  if (ts.isPropertyAccessExpression(bare.expression) && ts.isIdentifier(bare.expression.expression)) {
    const r = bare.expression.expression.text.toLowerCase();
    const m = bare.expression.name.text.toLowerCase();
    const methods = SANITIZER_RECEIVER_METHODS[r];
    return Boolean(methods && methods[m]);
  }
  return false;
}

function paramNameImpliesExternalContent(name: string): boolean {
  const lower = name.toLowerCase();
  for (const token of EXT_PARAM_TOKENS) {
    if (lower === token || lower.includes(token)) return true;
  }
  return false;
}

// ─── Response-call classification ──────────────────────────────────────────

function isResponseCall(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const method = call.expression.name.text.toLowerCase();
  if (!RESPONSE_METHOD_SET.has(method)) return false;
  const receiver = call.expression.expression;
  if (!ts.isIdentifier(receiver)) return false;
  return RESPONSE_RECEIVER_SET.has(receiver.text.toLowerCase());
}

// ─── Sanitizer check ───────────────────────────────────────────────────────

/**
 * Walk the enclosing function body searching for a sanitizer call whose
 * argument is a reference to the given identifier. If no identifier is
 * known (anonymous taint chain), fall back to "any sanitizer call seen
 * in the body" with a sameVariable=false flag.
 */
function sanitizerAppliedTo(
  body: ts.Node,
  identifier: string | null,
): { present: boolean; sameVariable: boolean; detail: string } {
  let anySanitizer = false;
  let sameVariable = false;
  let detail = "no sanitizer call observed in the enclosing function body";

  function visit(n: ts.Node): void {
    if (!ts.isCallExpression(n)) {
      ts.forEachChild(n, visit);
      return;
    }
    // Bare call: sanitize(x)
    if (ts.isIdentifier(n.expression) && SANITIZER_CALL_SET.has(n.expression.text.toLowerCase())) {
      anySanitizer = true;
      if (identifier !== null && callArgumentsReferenceIdentifier(n, identifier)) {
        sameVariable = true;
        detail = `sanitizer \`${n.expression.text}(...)\` applied to \`${identifier}\``;
        return;
      } else if (!sameVariable) {
        detail =
          identifier !== null
            ? `sanitizer \`${n.expression.text}(...)\` present but NOT applied to returned \`${identifier}\``
            : `sanitizer \`${n.expression.text}(...)\` present in scope`;
      }
    }
    // receiver.method: DOMPurify.sanitize(x), he.encode(x), …
    if (ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression)) {
      const r = n.expression.expression.text.toLowerCase();
      const m = n.expression.name.text.toLowerCase();
      const methods = SANITIZER_RECEIVER_METHODS[r];
      if (methods && methods[m]) {
        anySanitizer = true;
        if (identifier !== null && callArgumentsReferenceIdentifier(n, identifier)) {
          sameVariable = true;
          detail = `sanitizer \`${r}.${m}(...)\` applied to \`${identifier}\``;
          return;
        } else if (!sameVariable) {
          detail =
            identifier !== null
              ? `sanitizer \`${r}.${m}(...)\` present but NOT applied to returned \`${identifier}\``
              : `sanitizer \`${r}.${m}(...)\` present in scope`;
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(body);
  return { present: anySanitizer, sameVariable, detail };
}

function callArgumentsReferenceIdentifier(call: ts.CallExpression, name: string): boolean {
  for (const arg of call.arguments) {
    if (identifierAppearsInExpression(arg, name)) return true;
  }
  return false;
}

function identifierAppearsInExpression(expr: ts.Node, name: string): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && n.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

// ─── Location helpers ──────────────────────────────────────────────────────

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  const lines = sf.text.split("\n");
  return lines[line] ?? "";
}
