/**
 * K2 — Audit Trail Destruction: fact gathering.
 *
 * Structural AST scan. The rule emits a K2Fact when any of these three
 * shapes appear in the source:
 *
 *   (a) A destruction sink (fs.unlink / fs.truncate / os.remove / ...)
 *       whose path argument expression contains an audit-identifier
 *       token.
 *   (b) An empty-write sink (fs.writeFileSync with "" / Buffer.alloc(0)
 *       / Buffer.from("") as second arg) on the same path shape.
 *   (c) A logger-disable primitive (logging.disable(...),
 *       logger.silent = true, logger.level = "silent",
 *       audit.disable()). No path token required — the toggle itself is
 *       the violation.
 *
 * For each K2Fact the gatherer also records whether a rotation /
 * archive marker was observed in the enclosing function scope; if it
 * was, severity drops to "high" (still a violation — rotation without
 * retention is not compliant — but less severe than a bare unlink).
 *
 * Zero regex, zero string arrays > 5. Data lives in `./data/config.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  K2_DESTRUCTION_SINKS,
  K2_EMPTY_WRITE_SINKS,
  K2_LOGGER_DISABLE_SINKS,
  K2_AUDIT_PATH_MARKERS,
  K2_ROTATION_MARKERS,
  type DestructionSink,
  type LoggerDisableSink,
  type AuditPathMarker,
  type RotationMarker,
} from "./data/config.js";

// ─── Fact types emitted to index.ts ──────────────────────────────────────

export interface DestructionFact {
  readonly kind: "destruction";
  readonly sink: DestructionSink;
  readonly sinkLocation: Location;
  readonly sinkObserved: string;
  /** The literal path text — verbatim audit file path a reviewer reads. */
  readonly pathExpression: string;
  readonly pathLocation: Location;
  /** Which audit-identifier tokens matched the path expression. */
  readonly pathMarkers: readonly AuditPathMarker[];
  /** Rotation marker in the enclosing scope (severity downgrade). */
  readonly rotationMarker: RotationMarker | null;
  readonly rotationMarkerLocation: Location | null;
}

export interface LoggerDisableFact {
  readonly kind: "logger-disable";
  readonly sink: LoggerDisableSink;
  readonly sinkLocation: Location;
  readonly sinkObserved: string;
}

export type K2Fact = DestructionFact | LoggerDisableFact;

export interface K2GatherResult {
  readonly mode: "absent" | "test-file" | "facts";
  readonly file: string;
  readonly facts: readonly K2Fact[];
}

// ─── Gather ──────────────────────────────────────────────────────────────

const SYNTHETIC_FILE = "<source>";

export function gatherK2(context: AnalysisContext): K2GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", file: SYNTHETIC_FILE, facts: [] };
  }
  if (isTestFileShape(source)) {
    return { mode: "test-file", file: SYNTHETIC_FILE, facts: [] };
  }

  const sf = ts.createSourceFile(SYNTHETIC_FILE, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const facts: K2Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const destruction = analyzeDestructionCall(node, sf);
      if (destruction) facts.push(destruction);

      const emptyWrite = analyzeEmptyWriteCall(node, sf);
      if (emptyWrite) facts.push(emptyWrite);

      const loggerCall = analyzeLoggerDisableCall(node, sf);
      if (loggerCall) facts.push(loggerCall);
    }
    if (ts.isBinaryExpression(node)) {
      const silent = analyzeSilentAssignment(node, sf);
      if (silent) facts.push(silent);
    }
    ts.forEachChild(node, visit);
  });

  return {
    mode: facts.length > 0 ? "facts" : "absent",
    file: SYNTHETIC_FILE,
    facts,
  };
}

// ─── Test-file detection ─────────────────────────────────────────────────

function isTestFileShape(source: string): boolean {
  return (
    source.includes("__tests__") ||
    source.includes(".test.") ||
    source.includes(".spec.") ||
    source.includes("from \"vitest\"") ||
    source.includes("describe(")
  );
}

// ─── Destruction-call analysis ───────────────────────────────────────────

function analyzeDestructionCall(
  node: ts.CallExpression,
  sf: ts.SourceFile,
): DestructionFact | null {
  const callee = renderCallee(node.expression);
  const sink = matchDestructionSink(callee);
  if (!sink) return null;

  const pathArg = node.arguments[sink.pathArgIdx];
  if (!pathArg) return null;

  const pathText = pathArg.getText(sf);
  const markers = matchAuditMarkers(pathText);
  if (markers.length === 0) return null;

  return buildDestructionFact(node, sf, sink, pathArg, pathText, markers);
}

function analyzeEmptyWriteCall(
  node: ts.CallExpression,
  sf: ts.SourceFile,
): DestructionFact | null {
  const callee = renderCallee(node.expression);
  const sink = matchEmptyWriteSink(callee);
  if (!sink) return null;
  if (node.arguments.length < 2) return null;

  const pathArg = node.arguments[0];
  const contentArg = node.arguments[1];

  if (!isEmptyContent(contentArg)) return null;

  const pathText = pathArg.getText(sf);
  const markers = matchAuditMarkers(pathText);
  if (markers.length === 0) return null;

  return buildDestructionFact(node, sf, sink, pathArg, pathText, markers);
}

function buildDestructionFact(
  node: ts.CallExpression,
  sf: ts.SourceFile,
  sink: DestructionSink,
  pathArg: ts.Node,
  pathText: string,
  markers: readonly AuditPathMarker[],
): DestructionFact {
  const rotation = findRotationInEnclosingScope(node, sf);
  const nodeStart = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  const pathStart = sf.getLineAndCharacterOfPosition(pathArg.getStart(sf));
  return {
    kind: "destruction",
    sink,
    sinkLocation: { kind: "source", file: sf.fileName, line: nodeStart.line + 1, col: nodeStart.character + 1 },
    sinkObserved: node.getText(sf).slice(0, 160),
    pathExpression: pathText.slice(0, 160),
    pathLocation: { kind: "source", file: sf.fileName, line: pathStart.line + 1, col: pathStart.character + 1 },
    pathMarkers: markers,
    rotationMarker: rotation?.marker ?? null,
    rotationMarkerLocation: rotation?.location ?? null,
  };
}

function matchDestructionSink(callee: string): DestructionSink | null {
  for (const sink of K2_DESTRUCTION_SINKS) {
    if (sink.name === callee) return sink;
  }
  return null;
}

function matchEmptyWriteSink(callee: string): DestructionSink | null {
  for (const sink of K2_EMPTY_WRITE_SINKS) {
    if (sink.name === callee) return sink;
  }
  return null;
}

function isEmptyContent(arg: ts.Node): boolean {
  // Empty string literal.
  if (ts.isStringLiteral(arg) && arg.text === "") return true;
  if (ts.isNoSubstitutionTemplateLiteral(arg) && arg.text === "") return true;
  // Buffer.alloc(0)
  if (ts.isCallExpression(arg)) {
    const callee = renderCallee(arg.expression);
    if (callee === "Buffer.alloc" && arg.arguments.length === 1) {
      const first = arg.arguments[0];
      if (ts.isNumericLiteral(first) && first.text === "0") return true;
    }
    if (callee === "Buffer.from" && arg.arguments.length >= 1) {
      const first = arg.arguments[0];
      if (ts.isStringLiteral(first) && first.text === "") return true;
    }
  }
  return false;
}

function matchAuditMarkers(pathText: string): AuditPathMarker[] {
  const lower = pathText.toLowerCase();
  const out: AuditPathMarker[] = [];
  for (const marker of K2_AUDIT_PATH_MARKERS) {
    if (lower.includes(marker.token.toLowerCase())) out.push(marker);
  }
  return out;
}

// ─── Logger-disable analysis ─────────────────────────────────────────────

function analyzeLoggerDisableCall(
  node: ts.CallExpression,
  sf: ts.SourceFile,
): LoggerDisableFact | null {
  const callee = renderCallee(node.expression);
  for (const sink of K2_LOGGER_DISABLE_SINKS) {
    if (sink.shape !== "qualified-function") continue;
    if (sink.name === callee) {
      return toLoggerDisableFact(node, sf, sink);
    }
    // Also accept `logging.disable` path where the receiver differs
    // (e.g. `somelogger.disable` wasn't explicitly listed but the call
    // shape `somelogger.disable()` appears). The charter treats
    // audit.disable() as a first-class primitive.
  }
  return null;
}

function analyzeSilentAssignment(
  node: ts.BinaryExpression,
  sf: ts.SourceFile,
): LoggerDisableFact | null {
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return null;
  if (!ts.isPropertyAccessExpression(node.left)) return null;
  const propName = node.left.name.text;

  if (propName === "silent") {
    if (node.right.kind !== ts.SyntaxKind.TrueKeyword) return null;
    const sink = K2_LOGGER_DISABLE_SINKS.find((s) => s.shape === "silent-property-assignment");
    if (!sink) return null;
    return toLoggerDisableFact(node, sf, sink);
  }

  if (propName === "level") {
    if (!ts.isStringLiteral(node.right) && !ts.isNoSubstitutionTemplateLiteral(node.right)) return null;
    if (node.right.text !== "silent") return null;
    const sink = K2_LOGGER_DISABLE_SINKS.find((s) => s.shape === "level-property-assignment");
    if (!sink) return null;
    return toLoggerDisableFact(node, sf, sink);
  }

  return null;
}

function toLoggerDisableFact(
  node: ts.Node,
  sf: ts.SourceFile,
  sink: LoggerDisableSink,
): LoggerDisableFact {
  const start = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return {
    kind: "logger-disable",
    sink,
    sinkLocation: { kind: "source", file: sf.fileName, line: start.line + 1, col: start.character + 1 },
    sinkObserved: node.getText(sf).slice(0, 160),
  };
}

// ─── Rotation-marker detection ───────────────────────────────────────────

function findRotationInEnclosingScope(
  node: ts.Node,
  sf: ts.SourceFile,
): { marker: RotationMarker; location: Location } | null {
  const enclosing = findEnclosingFunction(node);
  if (!enclosing) return null;
  const bodyText = enclosing.getText(sf).toLowerCase();
  for (const marker of K2_ROTATION_MARKERS) {
    if (bodyText.includes(marker.token.toLowerCase())) {
      const start = sf.getLineAndCharacterOfPosition(enclosing.getStart(sf));
      return {
        marker,
        location: {
          kind: "source",
          file: sf.fileName,
          line: start.line + 1,
          col: start.character + 1,
        },
      };
    }
  }
  return null;
}

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let n: ts.Node | undefined = node.parent;
  while (n) {
    if (
      ts.isFunctionDeclaration(n) ||
      ts.isFunctionExpression(n) ||
      ts.isArrowFunction(n) ||
      ts.isMethodDeclaration(n) ||
      ts.isSourceFile(n)
    ) {
      return n;
    }
    n = n.parent;
  }
  return null;
}

// ─── AST helpers ─────────────────────────────────────────────────────────

function renderCallee(expr: ts.Node): string {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    return `${renderCallee(expr.expression)}.${expr.name.text}`;
  }
  return "";
}
