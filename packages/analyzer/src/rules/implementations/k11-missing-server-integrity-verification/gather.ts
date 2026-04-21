/**
 * K11 gather — missing server integrity verification.
 *
 * Fires when a runtime loader (dynamic import, require call with a
 * runtime-derived specifier, MCPClient / transport constructor fed with
 * runtime inputs, shell-mediated fetch+execute, runtime npm install)
 * appears on a non-test code path AND no integrity evidence is observable
 * anywhere on the lexical ancestor chain up to file scope.
 *
 * Zero regex. All vocabulary lives in `./data/loader-vocabulary.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  RUNTIME_LOADER_CALL_IDENTIFIERS,
  MCP_SERVER_CTOR_IDENTIFIERS,
  SERVER_LOAD_RECEIVER_METHODS,
  SUBPROCESS_CALL_IDENTIFIERS,
  NETWORK_FETCH_TOKENS,
  EVALUATOR_TOKENS,
  RUNTIME_INSTALL_TOKENS,
  INTEGRITY_CALL_IDENTIFIERS,
  INTEGRITY_RECEIVER_METHODS,
  INTEGRITY_FILENAME_TOKENS,
  INTEGRITY_IDENTIFIER_SUBSTRINGS,
  TEST_RUNNER_MODULES,
  TEST_RUNNER_TOPLEVEL,
} from "./data/loader-vocabulary.js";

// ─── Vocabulary sets ───────────────────────────────────────────────────────

const RUNTIME_LOADER_CALL_SET: ReadonlySet<string> = new Set(
  Object.keys(RUNTIME_LOADER_CALL_IDENTIFIERS),
);
const MCP_SERVER_CTOR_SET: ReadonlySet<string> = new Set(
  Object.keys(MCP_SERVER_CTOR_IDENTIFIERS),
);
const SUBPROCESS_CALL_SET: ReadonlySet<string> = new Set(
  Object.keys(SUBPROCESS_CALL_IDENTIFIERS),
);
const NETWORK_FETCH_SET: ReadonlySet<string> = new Set(Object.keys(NETWORK_FETCH_TOKENS));
const EVALUATOR_SET: ReadonlySet<string> = new Set(Object.keys(EVALUATOR_TOKENS));
const RUNTIME_INSTALL_SET: ReadonlySet<string> = new Set(Object.keys(RUNTIME_INSTALL_TOKENS));
const INTEGRITY_CALL_SET: ReadonlySet<string> = new Set(Object.keys(INTEGRITY_CALL_IDENTIFIERS));
const INTEGRITY_FILENAME_SET: ReadonlySet<string> = new Set(
  Object.keys(INTEGRITY_FILENAME_TOKENS),
);
const INTEGRITY_ID_SUBSTRINGS: ReadonlySet<string> = new Set(
  Object.keys(INTEGRITY_IDENTIFIER_SUBSTRINGS),
);
const TEST_MODULE_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_MODULES));
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_TOPLEVEL));

// ─── Public types ──────────────────────────────────────────────────────────

export type LoaderKind =
  | "dynamic-import"
  | "require-call"
  | "mcp-server-ctor"
  | "server-load-method"
  | "shell-fetch-execute"
  | "runtime-install";

export interface LoaderSite {
  location: Location; // kind: "source"
  kind: LoaderKind;
  observed: string; // snippet (<200 chars)
  calleeLabel: string; // short label: require / import() / new MCPClient / spawn-curl-bash
  /** Enclosing function Location, when the call sits inside one. */
  enclosingFunctionLocation: Location | null;
  /** Integrity evidence seen anywhere on the ancestor chain up to file scope. */
  integrityMitigation: {
    present: boolean;
    markers: string[]; // e.g. ["createHash-call", "integrity.json-literal"]
  };
}

export interface FileEvidence {
  file: string;
  isTestFile: boolean;
  sites: LoaderSite[];
}

export interface K11Gathered {
  perFile: FileEvidence[];
}

// ─── Entry ─────────────────────────────────────────────────────────────────

export function gatherK11(context: AnalysisContext): K11Gathered {
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
  const sites: LoaderSite[] = [];

  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      const kind = classifyLoaderNode(node, sf);
      if (kind) {
        const site = buildSite(node, kind, sf, file);
        if (site) sites.push(site);
      }
      ts.forEachChild(node, visit);
    });
  }

  return { file, isTestFile, sites };
}

// ─── Test-file detection (AST shape, not filename) ─────────────────────────

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

// ─── Loader classification ────────────────────────────────────────────────

/**
 * Inspect a single AST node and decide whether it is a runtime loader site.
 * Only the inbound node is checked — the tree walk is done by the caller.
 */
function classifyLoaderNode(node: ts.Node, _sf: ts.SourceFile): LoaderKind | null {
  // import(x) — dynamic import
  if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
    return "dynamic-import";
  }

  // require(x) — only fire when the specifier is NOT a static string literal.
  // A `require("bunyan")` call is resolved against the lockfile at install
  // time; only runtime-derived specifiers (`require(userPath)`) are the
  // supply-chain threat K11 names.
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
    const id = node.expression.text.toLowerCase();
    if (RUNTIME_LOADER_CALL_SET.has(id)) {
      if (requireSpecifierIsDynamic(node)) return "require-call";
      return null;
    }

    // subprocess calls: exec("curl … | bash"), spawn("sh", ["-c", "wget … && node"])
    if (SUBPROCESS_CALL_SET.has(id)) {
      const argvText = flattenArgvText(node);
      if (argvText.length > 0) {
        if (argvContainsRuntimeInstall(argvText)) return "runtime-install";
        if (argvContainsFetchAndEvaluator(argvText)) return "shell-fetch-execute";
      }
      return null;
    }
  }

  // receiver.method(): subprocess via child_process.exec / execSync
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    ts.isIdentifier(node.expression.expression)
  ) {
    const receiver = node.expression.expression.text.toLowerCase();
    const method = node.expression.name.text.toLowerCase();

    // subprocess via child_process / cp
    if (
      (receiver === "child_process" || receiver === "cp" || receiver === "proc" || receiver === "shell") &&
      SUBPROCESS_CALL_SET.has(method)
    ) {
      const argvText = flattenArgvText(node);
      if (argvText.length > 0) {
        if (argvContainsRuntimeInstall(argvText)) return "runtime-install";
        if (argvContainsFetchAndEvaluator(argvText)) return "shell-fetch-execute";
      }
      return null;
    }

    // Server-load receiver.method pairs (mcp.connect, server.loadPlugin, …).
    // Like new MCPClient(...), only the runtime-derived-input variant is a
    // K11 threat — a static specifier resolves through the lockfile.
    const methods = SERVER_LOAD_RECEIVER_METHODS[receiver];
    if (methods && methods[method]) {
      if (callHasDynamicInput(node)) return "server-load-method";
      return null;
    }
  }

  // new MCPClient(...), new StdioClientTransport(...). Fires only when the
  // construction references a runtime-derived value (an Identifier, member
  // access, or template expression) — pure static configuration is
  // lockfile-safe.
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
    if (
      MCP_SERVER_CTOR_SET.has(node.expression.text.toLowerCase()) &&
      newExpressionHasDynamicInput(node)
    ) {
      return "mcp-server-ctor";
    }
  }

  return null;
}

/** `require("foo")` → false (static, lockfile-resolvable); `require(x)` → true. */
function requireSpecifierIsDynamic(call: ts.CallExpression): boolean {
  if (call.arguments.length === 0) return false;
  const arg = call.arguments[0];
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return false;
  return true;
}

/** True if any argument to `new Foo(...)` is not a pure static literal. */
function newExpressionHasDynamicInput(ne: ts.NewExpression): boolean {
  if (!ne.arguments || ne.arguments.length === 0) return false;
  for (const arg of ne.arguments) {
    if (!isPureStaticInput(arg)) return true;
  }
  return false;
}

/** True if any argument to `f(...)` is not a pure static literal. */
function callHasDynamicInput(call: ts.CallExpression): boolean {
  if (call.arguments.length === 0) return false;
  for (const arg of call.arguments) {
    if (!isPureStaticInput(arg)) return true;
  }
  return false;
}

/**
 * Conservative: true only when the expression is demonstrably static (a
 * string literal, boolean/number literal, or an object literal whose every
 * value is itself static). Anything else (Identifier, PropertyAccess,
 * template expression with spans, array of non-literals) is treated as
 * runtime-derived.
 */
function isPureStaticInput(expr: ts.Expression): boolean {
  if (
    ts.isStringLiteral(expr) ||
    ts.isNoSubstitutionTemplateLiteral(expr) ||
    ts.isNumericLiteral(expr) ||
    expr.kind === ts.SyntaxKind.TrueKeyword ||
    expr.kind === ts.SyntaxKind.FalseKeyword ||
    expr.kind === ts.SyntaxKind.NullKeyword
  ) {
    return true;
  }
  if (ts.isArrayLiteralExpression(expr)) {
    return expr.elements.every(isPureStaticInput);
  }
  if (ts.isObjectLiteralExpression(expr)) {
    for (const prop of expr.properties) {
      if (ts.isPropertyAssignment(prop)) {
        if (!isPureStaticInput(prop.initializer)) return false;
      } else {
        // Shorthand property, spread, method — treat as runtime.
        return false;
      }
    }
    return true;
  }
  return false;
}

function flattenArgvText(call: ts.CallExpression): string {
  const parts: string[] = [];
  for (const arg of call.arguments) {
    collectStringLiterals(arg, parts);
  }
  return parts.join(" ").toLowerCase();
}

function collectStringLiterals(node: ts.Node, out: string[]): void {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    out.push(node.text);
    return;
  }
  if (ts.isTemplateExpression(node)) {
    out.push(node.head.text);
    for (const span of node.templateSpans) out.push(span.literal.text);
    return;
  }
  if (ts.isArrayLiteralExpression(node)) {
    for (const el of node.elements) collectStringLiterals(el, out);
    return;
  }
}

function argvContainsFetchAndEvaluator(argv: string): boolean {
  const tokens = tokenizeArgv(argv);
  let sawFetch = false;
  let sawEvaluator = false;
  for (const t of tokens) {
    if (NETWORK_FETCH_SET.has(t)) sawFetch = true;
    if (EVALUATOR_SET.has(t)) sawEvaluator = true;
  }
  return sawFetch && sawEvaluator;
}

function argvContainsRuntimeInstall(argv: string): boolean {
  const tokens = tokenizeArgv(argv);
  // `npm install`, `pnpm add`, `yarn add`, `pip install`, etc.
  // Look for "install"/"add"/"i" or "get-pip" adjacent to a package-manager-ish token.
  const hasInstall = tokens.some((t) => RUNTIME_INSTALL_SET.has(t));
  const hasPackageManager = tokens.some(
    (t) => t === "npm" || t === "pnpm" || t === "yarn" || t === "pip" || t === "pip3" || t === "bun",
  );
  return hasInstall && hasPackageManager;
}

/** Tokenise a shell argv string on whitespace, pipe, semicolon, ampersand. */
function tokenizeArgv(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (const ch of text) {
    if (ch === " " || ch === "\t" || ch === "|" || ch === ";" || ch === "&" || ch === "\n") {
      if (cur.length > 0) {
        out.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

// ─── Per-site build (Location + mitigation walk) ───────────────────────────

function buildSite(
  node: ts.Node,
  kind: LoaderKind,
  sf: ts.SourceFile,
  file: string,
): LoaderSite | null {
  const loc = sourceLocation(sf, file, node);
  const calleeLabel = renderCalleeLabel(node, kind);
  const enclosing = findEnclosingFunction(node);
  const enclosingLoc: Location | null = enclosing
    ? sourceLocation(sf, file, enclosing)
    : null;

  const integrity = walkAncestorsForIntegrity(node, sf);

  return {
    location: loc,
    kind,
    observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
    calleeLabel,
    enclosingFunctionLocation: enclosingLoc,
    integrityMitigation: integrity,
  };
}

function renderCalleeLabel(node: ts.Node, kind: LoaderKind): string {
  if (ts.isCallExpression(node)) {
    if (node.expression.kind === ts.SyntaxKind.ImportKeyword) return "import()";
    if (ts.isIdentifier(node.expression)) return `${node.expression.text}(...)`;
    if (ts.isPropertyAccessExpression(node.expression)) {
      const r = ts.isIdentifier(node.expression.expression)
        ? node.expression.expression.text
        : "?";
      return `${r}.${node.expression.name.text}(...)`;
    }
  }
  if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
    return `new ${node.expression.text}(...)`;
  }
  return kind;
}

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isConstructorDeclaration(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

/**
 * Walk the lexical ancestor chain from the node up to file scope, inspecting
 * each enclosing function body for integrity evidence. The walk also inspects
 * the file's top-level statements (integrity verified once at boot).
 *
 * Evidence counted:
 *   - CallExpression whose callee identifier or receiver.method matches the
 *     integrity vocabulary,
 *   - VariableDeclaration whose NAME contains an integrity substring,
 *   - StringLiteral matching an integrity filename (manifest file reference).
 */
function walkAncestorsForIntegrity(
  node: ts.Node,
  sf: ts.SourceFile,
): { present: boolean; markers: string[] } {
  const markers: string[] = [];

  // 1. Enclosing function bodies up to file scope.
  let cur: ts.Node | undefined = node.parent;
  while (cur && cur !== sf) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isConstructorDeclaration(cur) ||
      ts.isBlock(cur)
    ) {
      collectIntegrityEvidenceInScope(cur, markers);
    }
    cur = cur.parent;
  }

  // 2. File-scope top-level statements (boot-time integrity check).
  for (const stmt of sf.statements) {
    collectIntegrityEvidenceInScope(stmt, markers);
  }

  return { present: markers.length > 0, markers };
}

function collectIntegrityEvidenceInScope(scope: ts.Node, markers: string[]): void {
  function visit(n: ts.Node): void {
    // CallExpression — integrity vocabulary bare call OR receiver.method
    if (ts.isCallExpression(n)) {
      if (ts.isIdentifier(n.expression)) {
        const id = n.expression.text.toLowerCase();
        if (INTEGRITY_CALL_SET.has(id)) markers.push(`${id}-call`);
      } else if (ts.isPropertyAccessExpression(n.expression)) {
        if (ts.isIdentifier(n.expression.expression)) {
          const r = n.expression.expression.text.toLowerCase();
          const m = n.expression.name.text.toLowerCase();
          const methods = INTEGRITY_RECEIVER_METHODS[r];
          if (methods && methods[m]) markers.push(`${r}.${m}-call`);
        }
      }
    }
    // VariableDeclaration — integrity-bearing identifier
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name)) {
      if (identifierContainsIntegrityToken(n.name.text)) {
        markers.push(`var-${n.name.text}`);
      }
    }
    // ParameterDeclaration — integrity-bearing parameter (e.g. `(expectedSha256)`)
    if (ts.isParameter(n) && ts.isIdentifier(n.name)) {
      if (identifierContainsIntegrityToken(n.name.text)) {
        markers.push(`param-${n.name.text}`);
      }
    }
    // StringLiteral — integrity filename reference
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      const v = n.text.toLowerCase();
      if (INTEGRITY_FILENAME_SET.has(v)) markers.push(`file-${v}`);
    }
    ts.forEachChild(n, visit);
  }
  visit(scope);
}

function identifierContainsIntegrityToken(name: string): boolean {
  const lower = name.toLowerCase();
  for (const token of INTEGRITY_ID_SUBSTRINGS) {
    if (lower.includes(token)) return true;
  }
  return false;
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
