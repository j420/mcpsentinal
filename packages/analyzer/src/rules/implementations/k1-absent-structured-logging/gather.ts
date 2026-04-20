/**
 * K1 evidence gathering — deterministic, AST-only.
 *
 * The threat researcher's charter (CHARTER.md in this directory) specifies
 * the edge cases. This file is the engineer's translation into structural
 * queries. It does NOT import or produce a finding — `index.ts` consumes the
 * gathered facts and builds the evidence chain.
 *
 * No regex literals. No string-literal arrays of length > 5. Every canonical
 * list (logger package names, handler method names) is loaded from the
 * `./data/*.json` sibling files at module load.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import { LOGGERS, INDIRECT_LOGGER_FUNCTION_NAMES, type Ecosystem } from "./data/structured-loggers.js";
import {
  HTTP_METHODS,
  MCP_SERVER_METHODS,
  NEXTJS_HANDLER_NAMES,
} from "./data/handler-methods.js";

// ─── Registry derivation ───────────────────────────────────────────────────

const LOGGER_PACKAGES: ReadonlySet<string> = new Set(Object.keys(LOGGERS));

/**
 * `pino`, `winston`, `bunyan` and similar — the import specifier we look
 * for when scanning `import X from "..."` / `require("...")`. A subset of
 * LOGGER_PACKAGES: only the ones whose root package itself is the logger
 * (not accessory packages like `winston-transport`).
 */
const PRIMARY_LOGGER_SPECIFIERS: ReadonlySet<string> = new Set(
  Object.entries(LOGGERS)
    .filter(([, v]) => v.defaultImport !== null)
    .map(([k]) => k),
);

const INDIRECT_LOGGER_NAMES: ReadonlySet<string> = new Set(INDIRECT_LOGGER_FUNCTION_NAMES);

const HTTP_HANDLER_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(HTTP_METHODS));
const MCP_HANDLER_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(MCP_SERVER_METHODS));
const NEXTJS_HANDLER_NAME_SET: ReadonlySet<string> = new Set(Object.keys(NEXTJS_HANDLER_NAMES));

// ─── Public types ──────────────────────────────────────────────────────────

export interface HandlerSite {
  /** Structured Location for the handler registration. */
  location: Location; // kind: "source"
  /** Short label for the handler ("app.post", "export GET", "server.setRequestHandler"). */
  label: string;
  /** AST scope — all console calls on these lines belong to this handler. */
  startLine: number;
  endLine: number;
  /** File the handler lives in (same as location.file when kind=source). */
  file: string;
}

export interface ConsoleCallSite {
  location: Location; // kind: "source"
  /** Which console method: "log" | "warn" | "error" | "info" | "debug" | "trace". */
  method: string;
  /** The verbatim line text, trimmed and length-capped. */
  observed: string;
  /** The surrounding handler, if any. Null = console call outside any handler. */
  enclosingHandler: HandlerSite | null;
}

export interface LoggerImportSite {
  location: Location; // kind: "source"
  /** The import specifier ("pino", "winston", ...). */
  packageName: string;
  /** The local binding name ("logger", "l", "pino", etc.). */
  localBinding: string;
}

export interface DisableLoggingSite {
  location: Location; // kind: "source"
  /** Observed text. */
  observed: string;
  /** Which kind of suppression ("logging.disable" | "logger.silent-assignment"). */
  variant: "logging.disable" | "logger.silent-assignment";
}

export interface FileEvidence {
  file: string;
  handlers: HandlerSite[];
  consoleCalls: ConsoleCallSite[];
  loggerImports: LoggerImportSite[];
  /** Local binding names that should be treated as "the logger" for handler-use checks. */
  loggerBindings: Set<string>;
  /** Handler scopes inside which a call to a logger binding was seen. */
  handlersUsingLogger: Set<HandlerSite>;
  disableSites: DisableLoggingSite[];
  isTestFile: boolean;
}

export interface K1Gathered {
  /** One entry per scanned file. */
  perFile: FileEvidence[];
  /** Across-all-files: a structured logger import was seen somewhere. */
  anyFileImportsLogger: boolean;
  /** A structured logger appears in package.json dependencies. */
  dependencyHasLogger: boolean;
  /** Structured Location pointing at the dependency entry (if present). */
  dependencyLocation: Location | null;
}

// ─── Gathering ─────────────────────────────────────────────────────────────

/**
 * Scan a single file's AST and collect K1 facts. The function is purely
 * read-only — it does not produce findings or Evidence links.
 */
export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const handlers: HandlerSite[] = [];
  const consoleCalls: ConsoleCallSite[] = [];
  const loggerImports: LoggerImportSite[] = [];
  const loggerBindings = new Set<string>();
  const handlersUsingLogger = new Set<HandlerSite>();
  const disableSites: DisableLoggingSite[] = [];

  const isTestFile = detectTestFile(sf);

  // Pass 1: collect logger imports and logger-like bindings.
  for (const stmt of sf.statements) {
    collectLoggerImport(stmt, sf, file, loggerImports, loggerBindings);
  }

  // Pass 1b: variable initializers anywhere — `const logger = someLoggerImport(...)`.
  ts.forEachChild(sf, function visit(node) {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const bindingName = node.name.text;
      if (
        callReturnsLogger(node.initializer, loggerBindings) ||
        isIdentifierInSet(node.initializer, loggerBindings)
      ) {
        loggerBindings.add(bindingName);
      }
    }
    ts.forEachChild(node, visit);
  });

  // Pass 2: walk the tree, detecting handlers, console calls, logger use, and suppressions.
  ts.forEachChild(sf, function visit(node) {
    const handler = detectHandlerRegistration(node, sf, file);
    if (handler) handlers.push(handler);

    if (ts.isFunctionDeclaration(node) && node.name) {
      const nextjs = detectNextjsHandler(node, sf, file);
      if (nextjs) handlers.push(nextjs);
    }

    if (ts.isCallExpression(node)) {
      const consoleSite = detectConsoleCall(node, sf, file);
      if (consoleSite) consoleCalls.push(consoleSite);

      const loggerUse = detectLoggerBindingUse(node, loggerBindings);
      if (loggerUse) {
        const enclosing = findEnclosingHandler(node, sf, handlers);
        if (enclosing) handlersUsingLogger.add(enclosing);
      }

      if (INDIRECT_LOGGER_NAMES.size > 0) {
        const indirect = detectIndirectLoggerCall(node, sf);
        if (indirect) {
          const enclosing = findEnclosingHandler(node, sf, handlers);
          if (enclosing) handlersUsingLogger.add(enclosing);
        }
      }

      const disable = detectDisableSuppression(node, sf, file);
      if (disable) disableSites.push(disable);
    }

    if (ts.isBinaryExpression(node)) {
      const silent = detectSilentAssignment(node, sf, file);
      if (silent) disableSites.push(silent);
    }

    ts.forEachChild(node, visit);
  });

  // Tag each console call with the handler it falls inside (if any).
  for (const call of consoleCalls) {
    const callLoc = call.location as Extract<Location, { kind: "source" }>;
    for (const handler of handlers) {
      if (callLoc.line >= handler.startLine && callLoc.line <= handler.endLine) {
        call.enclosingHandler = handler;
        break;
      }
    }
  }

  return {
    file,
    handlers,
    consoleCalls,
    loggerImports,
    loggerBindings,
    handlersUsingLogger,
    disableSites,
    isTestFile,
  };
}

/**
 * Gather K1 evidence across every available source file plus the dependency list.
 */
export function gatherK1(context: AnalysisContext): K1Gathered {
  const perFile: FileEvidence[] = [];

  const files = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) files.set(k, v);
  } else if (context.source_code) {
    // Degraded: single concatenated source. Use a synthetic filename.
    files.set("<concatenated-source>", context.source_code);
  }

  for (const [file, text] of files) {
    perFile.push(gatherFile(file, text));
  }

  const anyFileImportsLogger = perFile.some((f) => f.loggerImports.length > 0);

  const dependencyMatch = context.dependencies.find((d) => LOGGER_PACKAGES.has(d.name));
  const dependencyHasLogger = dependencyMatch !== undefined;
  const ecosystem: Ecosystem = LOGGERS[dependencyMatch?.name ?? ""]?.ecosystem ?? "npm";
  const dependencyLocation: Location | null = dependencyMatch
    ? {
        kind: "dependency",
        ecosystem,
        name: dependencyMatch.name,
        version: dependencyMatch.version ?? "unknown",
      }
    : null;

  return { perFile, anyFileImportsLogger, dependencyHasLogger, dependencyLocation };
}

// ─── AST helpers — intentionally small and single-purpose ──────────────────

function toLine(sf: ts.SourceFile, pos: number): { line: number; col: number } {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return { line: line + 1, col: character + 1 };
}

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = toLine(sf, node.getStart(sf));
  return { kind: "source", file, line: start.line, col: start.col };
}

/** `import pino from "pino"` / `import * as winston from "winston"` / CJS require. */
function collectLoggerImport(
  stmt: ts.Statement,
  sf: ts.SourceFile,
  file: string,
  imports: LoggerImportSite[],
  bindings: Set<string>,
): void {
  if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
    const pkg = stmt.moduleSpecifier.text;
    if (!PRIMARY_LOGGER_SPECIFIERS.has(pkg)) return;
    const clause = stmt.importClause;
    if (!clause) return;

    if (clause.name) {
      const binding = clause.name.text;
      imports.push({
        location: sourceLocation(sf, file, stmt),
        packageName: pkg,
        localBinding: binding,
      });
      bindings.add(binding);
    }
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
      const binding = clause.namedBindings.name.text;
      imports.push({
        location: sourceLocation(sf, file, stmt),
        packageName: pkg,
        localBinding: binding,
      });
      bindings.add(binding);
    }
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) {
        const binding = el.name.text;
        imports.push({
          location: sourceLocation(sf, file, stmt),
          packageName: pkg,
          localBinding: binding,
        });
        bindings.add(binding);
      }
    }
    return;
  }

  // `const x = require("pino")`
  if (ts.isVariableStatement(stmt)) {
    for (const decl of stmt.declarationList.declarations) {
      if (!decl.initializer || !ts.isCallExpression(decl.initializer)) continue;
      if (!ts.isIdentifier(decl.initializer.expression)) continue;
      if (decl.initializer.expression.text !== "require") continue;
      const arg = decl.initializer.arguments[0];
      if (!arg || !ts.isStringLiteral(arg)) continue;
      if (!PRIMARY_LOGGER_SPECIFIERS.has(arg.text)) continue;
      if (!ts.isIdentifier(decl.name)) continue;
      const binding = decl.name.text;
      imports.push({
        location: sourceLocation(sf, file, stmt),
        packageName: arg.text,
        localBinding: binding,
      });
      bindings.add(binding);
    }
  }
}

/** `app.get(...)`, `fastify.post(...)`, `server.setRequestHandler(...)`, etc. */
function detectHandlerRegistration(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): HandlerSite | null {
  if (!ts.isCallExpression(node)) return null;
  if (!ts.isPropertyAccessExpression(node.expression)) return null;

  const method = node.expression.name.text;
  const isHttp = HTTP_HANDLER_METHOD_SET.has(method);
  const isMcp = MCP_HANDLER_METHOD_SET.has(method);
  if (!isHttp && !isMcp) return null;

  // `server.on("request", ...)` needs the first arg to be "request" to count.
  if (method === "on") {
    const first = node.arguments[0];
    if (!first || !ts.isStringLiteral(first) || first.text !== "request") return null;
  }

  const startPos = node.getStart(sf);
  const endPos = node.getEnd();
  const start = toLine(sf, startPos);
  const end = toLine(sf, endPos);
  const receiver = node.expression.expression.getText(sf).trim();

  return {
    location: { kind: "source", file, line: start.line, col: start.col },
    label: `${receiver}.${method}`,
    startLine: start.line,
    endLine: end.line,
    file,
  };
}

/** Next.js App Router: `export async function GET(...)`, `export default async function handler(...)`. */
function detectNextjsHandler(
  node: ts.FunctionDeclaration,
  sf: ts.SourceFile,
  file: string,
): HandlerSite | null {
  if (!node.name) return null;
  const modifiers = ts.getModifiers(node);
  const isExported = modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
  if (!isExported) return null;
  if (!NEXTJS_HANDLER_NAME_SET.has(node.name.text)) return null;

  const start = toLine(sf, node.getStart(sf));
  const end = toLine(sf, node.getEnd());
  return {
    location: { kind: "source", file, line: start.line, col: start.col },
    label: `export function ${node.name.text}`,
    startLine: start.line,
    endLine: end.line,
    file,
  };
}

/** `console.log(...)` / `console.error(...)` / etc. */
function detectConsoleCall(
  node: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
): ConsoleCallSite | null {
  if (!ts.isPropertyAccessExpression(node.expression)) return null;
  const recv = node.expression.expression;
  if (!ts.isIdentifier(recv) || recv.text !== "console") return null;

  const method = node.expression.name.text;
  const start = toLine(sf, node.getStart(sf));
  const lineText = sf.text.split("\n")[start.line - 1] ?? "";
  return {
    location: { kind: "source", file, line: start.line, col: start.col },
    method,
    observed: lineText.trim().slice(0, 200),
    enclosingHandler: null,
  };
}

/** `logger.info(...)`, `l.warn(...)` — where the receiver was added to bindings. */
function detectLoggerBindingUse(
  node: ts.CallExpression,
  bindings: ReadonlySet<string>,
): boolean {
  if (bindings.size === 0) return false;
  if (!ts.isPropertyAccessExpression(node.expression)) return false;
  const recv = node.expression.expression;
  if (!ts.isIdentifier(recv)) return false;
  return bindings.has(recv.text);
}

/** `audit(req.body)` / `emit("...", ...)` — imported indirect-logger function names. */
function detectIndirectLoggerCall(node: ts.CallExpression, _sf: ts.SourceFile): boolean {
  if (!ts.isIdentifier(node.expression)) return false;
  return INDIRECT_LOGGER_NAMES.has(node.expression.text);
}

/** `logging.disable(logging.CRITICAL)`. */
function detectDisableSuppression(
  node: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
): DisableLoggingSite | null {
  if (!ts.isPropertyAccessExpression(node.expression)) return null;
  const recv = node.expression.expression;
  if (!ts.isIdentifier(recv) || recv.text !== "logging") return null;
  if (node.expression.name.text !== "disable") return null;
  const start = toLine(sf, node.getStart(sf));
  const lineText = sf.text.split("\n")[start.line - 1] ?? "";
  return {
    location: { kind: "source", file, line: start.line, col: start.col },
    observed: lineText.trim().slice(0, 200),
    variant: "logging.disable",
  };
}

/** `logger.silent = true` or `logger.level = "silent"`. */
function detectSilentAssignment(
  node: ts.BinaryExpression,
  sf: ts.SourceFile,
  file: string,
): DisableLoggingSite | null {
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return null;
  if (!ts.isPropertyAccessExpression(node.left)) return null;
  const propName = node.left.name.text;
  const silentProp = propName === "silent" || propName === "level";
  if (!silentProp) return null;
  if (propName === "level") {
    if (!ts.isStringLiteral(node.right) || node.right.text !== "silent") return null;
  } else {
    if (node.right.kind !== ts.SyntaxKind.TrueKeyword) return null;
  }
  const start = toLine(sf, node.getStart(sf));
  const lineText = sf.text.split("\n")[start.line - 1] ?? "";
  return {
    location: { kind: "source", file, line: start.line, col: start.col },
    observed: lineText.trim().slice(0, 200),
    variant: "logger.silent-assignment",
  };
}

// ─── Ancillary: test-file heuristics, alias resolution ─────────────────────

/**
 * A file is a test file if EITHER:
 *   - its name ends .test.ts / .spec.ts / .test.js etc.
 *   - OR it imports a test runner (vitest | jest | mocha) AND it uses top-level
 *     `describe(` / `it(` / `test(`.
 * The structural check prevents attackers hiding production code behind a
 * .test.ts name that is nevertheless wired into the entry point.
 */
function detectTestFile(sf: ts.SourceFile): boolean {
  const name = sf.fileName;
  const TEST_NAME_SUFFIXES = [".test.ts", ".test.js", ".spec.ts", ".spec.js"];
  const nameLooksLikeTest = TEST_NAME_SUFFIXES.some((s) => name.endsWith(s));

  const runnerImports = new Set<string>();
  let usesTopLevelSuite = false;

  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const spec = stmt.moduleSpecifier.text;
      if (spec === "vitest" || spec === "jest" || spec === "mocha") runnerImports.add(spec);
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee)) {
        if (callee.text === "describe" || callee.text === "it" || callee.text === "test") {
          usesTopLevelSuite = true;
        }
      }
    }
  }

  const structuralTest = runnerImports.size > 0 && usesTopLevelSuite;
  return nameLooksLikeTest || structuralTest;
}

/** Is `expr` a call like `<loggerBinding>(...)` or `<loggerBinding>.X(...)`? */
function callReturnsLogger(expr: ts.Expression, bindings: Set<string>): boolean {
  if (!ts.isCallExpression(expr)) return false;
  const head = expr.expression;
  if (ts.isIdentifier(head) && bindings.has(head.text)) return true;
  if (ts.isPropertyAccessExpression(head) && ts.isIdentifier(head.expression)) {
    return bindings.has(head.expression.text);
  }
  return false;
}

function isIdentifierInSet(expr: ts.Expression, set: Set<string>): boolean {
  return ts.isIdentifier(expr) && set.has(expr.text);
}

function findEnclosingHandler(
  node: ts.Node,
  sf: ts.SourceFile,
  handlers: ReadonlyArray<HandlerSite>,
): HandlerSite | null {
  const { line } = toLine(sf, node.getStart(sf));
  for (const h of handlers) {
    if (line >= h.startLine && line <= h.endLine) return h;
  }
  return null;
}
