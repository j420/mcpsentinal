/**
 * K20 evidence gathering — AST-only.
 *
 * For every log-call site in every analysable file, record:
 *   - the call's receiver shape (console / known-binding / child chain /
 *     indirect wrapper / unknown);
 *   - the call's method name (log/info/warn/...);
 *   - the observable audit-field aliases across all object-literal
 *     arguments AND any `.child(<obj>)` bindings on the receiver chain;
 *   - whether any observed object carries a SpreadAssignment (opaque
 *     context — defuses the emptiness verdict);
 *   - whether a structured logger is imported in this file (K1 vs K20
 *     boundary) and whether a mixin/format constructor is observed
 *     (invisible-fields mitigation).
 *
 * Zero regex literals, zero string-literal arrays > 5.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  AUDIT_FIELD_GROUPS,
  AUDIT_FIELD_THRESHOLD,
  buildAuditAliasSet,
  groupForAlias,
  type AuditFieldGroup,
} from "./data/audit-fields.js";
import {
  BINDINGS_METHOD_NAMES,
  CONVENTIONAL_LOGGER_IDENTIFIERS,
  INDIRECT_STRUCTURED_WRAPPERS,
  LOG_LEVEL_METHODS,
  MIXIN_FORMAT_CONSTRUCTORS,
  STRUCTURED_LOGGER_PACKAGES,
} from "./data/logger-vocabulary.js";

// ─── Registry derivation (module-load-time) ────────────────────────────────

const AUDIT_ALIAS_SET: ReadonlySet<string> = buildAuditAliasSet();
const LOGGER_PACKAGE_SET: ReadonlySet<string> = new Set(Object.keys(STRUCTURED_LOGGER_PACKAGES));
const CONVENTIONAL_LOGGER_SET: ReadonlySet<string> = new Set(
  Object.keys(CONVENTIONAL_LOGGER_IDENTIFIERS),
);
const LOG_LEVEL_SET: ReadonlySet<string> = new Set(Object.keys(LOG_LEVEL_METHODS));
const INDIRECT_WRAPPER_SET: ReadonlySet<string> = new Set(
  Object.keys(INDIRECT_STRUCTURED_WRAPPERS),
);
const BINDINGS_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(BINDINGS_METHOD_NAMES));

// ─── Public types ──────────────────────────────────────────────────────────

export type ReceiverShape =
  | "console"
  | "conventional-logger"
  | "imported-logger"
  | "child-chain"
  | "unknown";

export interface BindingsSite {
  /** Location of the .child(<obj>) call in the receiver chain. */
  location: Location;
  /** Audit-field aliases observed in the child()'s argument object(s). */
  observedAliases: string[];
}

export interface LoggerCallSite {
  /** Location of the whole call expression. */
  location: Location;
  /** Method on the receiver that was invoked — lowercased. */
  method: string;
  /** Receiver classification. */
  receiverShape: ReceiverShape;
  /** Text label for the receiver, for narrative rendering. */
  receiverLabel: string;
  /**
   * Distinct audit-field aliases observed at the call site plus any
   * `.child(<obj>)` bindings on the receiver chain. Lowercased.
   */
  observedAliases: Set<string>;
  /** Bindings-chain contributions (if any). */
  bindingsSites: BindingsSite[];
  /**
   * True if any observed object literal carries a SpreadAssignment. A
   * spread defuses the "empty object" verdict because the spread may
   * carry the required fields — acknowledged false-negative window.
   */
  hasOpaqueSpread: boolean;
  /** True if the call has at least one ObjectLiteralExpression argument. */
  hasObjectArgument: boolean;
  /** True if the call's only argument is a bare string / template literal. */
  isStringOnly: boolean;
  /** The verbatim line text, trimmed and length-capped, for `observed`. */
  observed: string;
  /** The file this call lives in. */
  file: string;
}

export interface MixinFormatSite {
  location: Location;
  observed: string;
}

export interface FileEvidence {
  file: string;
  calls: LoggerCallSite[];
  /** Imported structured logger package names (lowercased). */
  importedLoggerPackages: Set<string>;
  /** Local binding names that resolve to a structured logger import. */
  importedLoggerBindings: Set<string>;
  /** Mixin / winston-format constructors observed anywhere in the file. */
  mixinFormatSites: MixinFormatSite[];
  /** Whether the file is structurally a test file (skipped). */
  isTestFile: boolean;
}

export interface K20Gathered {
  perFile: FileEvidence[];
}

// ─── Public entry ──────────────────────────────────────────────────────────

export function gatherK20(context: AnalysisContext): K20Gathered {
  const perFile: FileEvidence[] = [];
  const files = collectSourceFiles(context);
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

export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  const importedLoggerPackages = new Set<string>();
  const importedLoggerBindings = new Set<string>();
  const mixinFormatSites: MixinFormatSite[] = [];
  const calls: LoggerCallSite[] = [];

  if (!isTestFile) {
    // Pass 1 — logger imports and bindings.
    for (const stmt of sf.statements) {
      collectLoggerImport(stmt, importedLoggerPackages, importedLoggerBindings);
    }

    // Pass 2 — mixin/format constructors (file-scope scan).
    ts.forEachChild(sf, function visit(node) {
      const mix = classifyMixinFormat(node, sf, file);
      if (mix) mixinFormatSites.push(mix);
      ts.forEachChild(node, visit);
    });

    // Pass 3 — log-call sites.
    ts.forEachChild(sf, function visit(node) {
      if (ts.isCallExpression(node)) {
        const site = classifyLogCall(node, sf, file, importedLoggerBindings);
        if (site) calls.push(site);
      }
      ts.forEachChild(node, visit);
    });
  }

  return {
    file,
    calls,
    importedLoggerPackages,
    importedLoggerBindings,
    mixinFormatSites,
    isTestFile,
  };
}

// ─── Import detection ──────────────────────────────────────────────────────

function collectLoggerImport(
  stmt: ts.Statement,
  packages: Set<string>,
  bindings: Set<string>,
): void {
  if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
    const pkg = stmt.moduleSpecifier.text;
    if (!LOGGER_PACKAGE_SET.has(pkg)) return;
    packages.add(pkg.toLowerCase());
    const clause = stmt.importClause;
    if (!clause) return;

    if (clause.name) bindings.add(clause.name.text);
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
      bindings.add(clause.namedBindings.name.text);
    }
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const el of clause.namedBindings.elements) {
        bindings.add(el.name.text);
      }
    }
    return;
  }

  // CommonJS: `const X = require("pino")`.
  if (ts.isVariableStatement(stmt)) {
    for (const decl of stmt.declarationList.declarations) {
      if (!decl.initializer || !ts.isCallExpression(decl.initializer)) continue;
      if (!ts.isIdentifier(decl.initializer.expression)) continue;
      if (decl.initializer.expression.text !== "require") continue;
      const arg = decl.initializer.arguments[0];
      if (!arg || !ts.isStringLiteral(arg)) continue;
      if (!LOGGER_PACKAGE_SET.has(arg.text)) continue;
      packages.add(arg.text.toLowerCase());
      if (ts.isIdentifier(decl.name)) bindings.add(decl.name.text);
    }
  }
}

// ─── Mixin / format constructor detection ──────────────────────────────────

function classifyMixinFormat(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): MixinFormatSite | null {
  if (!ts.isCallExpression(node)) return null;
  const expr = node.expression;

  // <receiver>.<method>() matches
  if (ts.isPropertyAccessExpression(expr)) {
    const recvText = expr.expression.getText(sf).toLowerCase();
    const method = expr.name.text.toLowerCase();
    const methods = MIXIN_FORMAT_CONSTRUCTORS[recvText];
    if (methods && methods[method]) {
      return { location: sourceLocation(sf, file, node), observed: truncateLineText(sf, node) };
    }
  }
  return null;
}

// ─── Log-call classification ───────────────────────────────────────────────

function classifyLogCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  importedBindings: ReadonlySet<string>,
): LoggerCallSite | null {
  // Indirect wrappers are deliberately NOT scanned (K1 strategy parity).
  if (isIndirectWrapperCall(call)) return null;

  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text.toLowerCase();
  if (!LOG_LEVEL_SET.has(method)) return null;

  // Receiver classification.
  const receiver = call.expression.expression;
  const shape = classifyReceiverShape(receiver, importedBindings);
  if (shape.shape === "unknown") return null;

  // Gather bindings sites by walking down .child(...) receivers.
  const bindingsSites: BindingsSite[] = [];
  let hasOpaqueSpread = false;
  collectBindingsFromReceiverChain(receiver, sf, file, bindingsSites, (spread) => {
    if (spread) hasOpaqueSpread = true;
  });

  // Inspect call arguments.
  const perCall = inspectCallArguments(call);
  if (perCall.hasSpread) hasOpaqueSpread = true;

  const observedAliases = new Set<string>();
  for (const alias of perCall.aliases) observedAliases.add(alias);
  for (const b of bindingsSites) {
    for (const alias of b.observedAliases) observedAliases.add(alias);
  }

  return {
    location: sourceLocation(sf, file, call),
    method,
    receiverShape: shape.shape,
    receiverLabel: shape.label,
    observedAliases,
    bindingsSites,
    hasOpaqueSpread,
    hasObjectArgument: perCall.hasObjectArgument,
    isStringOnly: perCall.isStringOnly,
    observed: truncateLineText(sf, call),
    file,
  };
}

function isIndirectWrapperCall(call: ts.CallExpression): boolean {
  // Bare call like `audit(req)` — no receiver.
  if (ts.isIdentifier(call.expression)) {
    return INDIRECT_WRAPPER_SET.has(call.expression.text.toLowerCase());
  }
  return false;
}

interface ReceiverClass {
  shape: ReceiverShape;
  label: string;
}

function classifyReceiverShape(
  receiver: ts.Expression,
  importedBindings: ReadonlySet<string>,
): ReceiverClass {
  // Direct identifier receiver.
  if (ts.isIdentifier(receiver)) {
    const name = receiver.text;
    if (name === "console") return { shape: "console", label: "console" };
    if (importedBindings.has(name)) {
      return { shape: "imported-logger", label: name };
    }
    if (CONVENTIONAL_LOGGER_SET.has(name.toLowerCase())) {
      return { shape: "conventional-logger", label: name };
    }
    return { shape: "unknown", label: name };
  }
  // `<x>.child(<obj>).info(...)` — the receiver is itself a CallExpression.
  if (ts.isCallExpression(receiver)) {
    const shape = classifyChildChainBase(receiver, importedBindings);
    if (shape) return shape;
  }
  // `<x>.<something>.info(...)` (namespace-style) — walk inward.
  if (ts.isPropertyAccessExpression(receiver)) {
    const base = receiver.expression;
    if (ts.isIdentifier(base)) {
      const name = base.text;
      if (name === "console") return { shape: "console", label: "console" };
      if (importedBindings.has(name)) {
        return { shape: "imported-logger", label: `${name}.${receiver.name.text}` };
      }
      if (CONVENTIONAL_LOGGER_SET.has(name.toLowerCase())) {
        return { shape: "conventional-logger", label: `${name}.${receiver.name.text}` };
      }
    }
  }
  return { shape: "unknown", label: "<unknown>" };
}

/**
 * If the receiver is a CallExpression whose callee is
 * `<base>.<bindings-method>`, return the base classification promoted
 * to "child-chain" — otherwise null.
 */
function classifyChildChainBase(
  call: ts.CallExpression,
  importedBindings: ReadonlySet<string>,
): ReceiverClass | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text;
  if (!BINDINGS_METHOD_SET.has(method)) return null;
  const base = call.expression.expression;
  const baseShape = classifyReceiverShape(base, importedBindings);
  if (baseShape.shape === "unknown") return null;
  return { shape: "child-chain", label: `${baseShape.label}.${method}` };
}

// ─── Argument & bindings inspection ────────────────────────────────────────

interface PerCallArgObservation {
  aliases: Set<string>;
  hasObjectArgument: boolean;
  hasSpread: boolean;
  isStringOnly: boolean;
}

function inspectCallArguments(call: ts.CallExpression): PerCallArgObservation {
  const aliases = new Set<string>();
  let hasObjectArgument = false;
  let hasSpread = false;
  let stringLikeCount = 0;
  let totalArgs = 0;

  for (const arg of call.arguments) {
    totalArgs++;
    if (ts.isObjectLiteralExpression(arg)) {
      hasObjectArgument = true;
      const obs = inspectObjectLiteral(arg);
      if (obs.hasSpread) hasSpread = true;
      for (const alias of obs.aliases) aliases.add(alias);
    } else if (
      ts.isStringLiteral(arg) ||
      ts.isNoSubstitutionTemplateLiteral(arg) ||
      ts.isTemplateExpression(arg)
    ) {
      stringLikeCount++;
    }
  }

  // "String-only" means every positional argument is a string literal /
  // template literal. Template literals with interpolation still count
  // as string-only per the fifth lethal edge case — text interpolation
  // is not structured logging.
  const isStringOnly = totalArgs > 0 && stringLikeCount === totalArgs;

  return { aliases, hasObjectArgument, hasSpread, isStringOnly };
}

interface ObjectLiteralObservation {
  aliases: Set<string>;
  hasSpread: boolean;
}

function inspectObjectLiteral(obj: ts.ObjectLiteralExpression): ObjectLiteralObservation {
  const aliases = new Set<string>();
  let hasSpread = false;
  for (const prop of obj.properties) {
    if (ts.isSpreadAssignment(prop)) {
      hasSpread = true;
      continue;
    }
    const name = propertyKeyName(prop);
    if (name === null) continue;
    if (AUDIT_ALIAS_SET.has(name.toLowerCase())) {
      aliases.add(name.toLowerCase());
    }
  }
  return { aliases, hasSpread };
}

function propertyKeyName(prop: ts.ObjectLiteralElementLike): string | null {
  if (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop) || ts.isMethodDeclaration(prop)) {
    const name = prop.name;
    if (ts.isIdentifier(name)) return name.text;
    if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) return name.text;
    if (ts.isPrivateIdentifier(name)) return name.text;
  }
  return null;
}

/**
 * Walk inward through a receiver chain collecting any `.child(<obj>)`
 * or equivalent bindings call. Fields are gathered from each such
 * object literal. `onSpread` is called with true when any observed
 * bindings object carries a SpreadAssignment.
 */
function collectBindingsFromReceiverChain(
  receiver: ts.Expression,
  sf: ts.SourceFile,
  file: string,
  sites: BindingsSite[],
  onSpread: (seen: boolean) => void,
): void {
  let cur: ts.Expression = receiver;
  // Prevent unbounded walks on malformed input.
  let safety = 8;
  while (safety-- > 0) {
    if (ts.isCallExpression(cur) && ts.isPropertyAccessExpression(cur.expression)) {
      const method = cur.expression.name.text;
      if (BINDINGS_METHOD_SET.has(method)) {
        const siteAliases: string[] = [];
        for (const arg of cur.arguments) {
          if (ts.isObjectLiteralExpression(arg)) {
            const obs = inspectObjectLiteral(arg);
            if (obs.hasSpread) onSpread(true);
            for (const alias of obs.aliases) siteAliases.push(alias);
          }
        }
        sites.push({
          location: sourceLocation(sf, file, cur),
          observedAliases: siteAliases,
        });
        // Recurse deeper: the base of child() may itself be a child() of
        // another logger.
        cur = cur.expression.expression;
        continue;
      }
      // Non-bindings method call — stop.
      return;
    }
    // Property access or identifier — chain terminates here.
    return;
  }
}

// ─── Evaluation helpers (public) ───────────────────────────────────────────

/**
 * Classify a call site's adequacy. Returns:
 *   - "insufficient" if the observed alias count is below the threshold
 *     AND the call is not defused by a SpreadAssignment;
 *   - "has-opaque-spread" if a spread defuses the verdict;
 *   - "adequate" otherwise.
 *
 * The rule fires only on "insufficient".
 */
export type CallAdequacy = "insufficient" | "has-opaque-spread" | "adequate";

export function classifyCallAdequacy(site: LoggerCallSite): CallAdequacy {
  if (site.observedAliases.size >= AUDIT_FIELD_THRESHOLD) return "adequate";
  if (site.hasOpaqueSpread) return "has-opaque-spread";
  return "insufficient";
}

/**
 * Compute which audit-field groups are missing from a call site's
 * observed alias set. Used by the narrative builder.
 */
export function missingGroups(site: LoggerCallSite): AuditFieldGroup[] {
  const presentGroups = new Set<AuditFieldGroup>();
  for (const alias of site.observedAliases) {
    const grp = groupForAlias(alias);
    if (grp) presentGroups.add(grp);
  }
  const out: AuditFieldGroup[] = [];
  for (const group of Object.keys(AUDIT_FIELD_GROUPS) as AuditFieldGroup[]) {
    if (!presentGroups.has(group)) out.push(group);
  }
  return out;
}

// ─── Test-file detection (structural) ──────────────────────────────────────

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelIt = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const spec = stmt.moduleSpecifier.text;
      if (spec === "vitest" || spec === "jest" || spec === "mocha" || spec === "@jest/globals") {
        hasRunnerImport = true;
      }
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee)) {
        const name = callee.text;
        if (name === "describe" || name === "it" || name === "test") topLevelIt++;
      }
    }
  }
  if (topLevelIt > 0 && hasRunnerImport) return true;
  // Fallback: filename heuristic for worktree contexts without imports.
  const filenameLikelyTest =
    sf.fileName.endsWith(".test.ts") ||
    sf.fileName.endsWith(".test.js") ||
    sf.fileName.endsWith(".spec.ts") ||
    sf.fileName.endsWith(".spec.js");
  return filenameLikelyTest;
}

// ─── AST position helpers ──────────────────────────────────────────────────

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function truncateLineText(sf: ts.SourceFile, node: ts.Node): string {
  const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const lines = sf.text.split("\n");
  return (lines[line] ?? "").trim().slice(0, 200);
}
