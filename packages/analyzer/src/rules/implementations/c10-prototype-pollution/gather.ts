/**
 * C10 — Prototype Pollution: deterministic AST-driven fact gathering.
 *
 * Detection strategy (no regex, no string-literal arrays > 5):
 *
 *   (a) MERGE-CALL DETECTION — walk every CallExpression. If the callee
 *       identifier or receiver.method name is in MERGE_FUNCTION_NAMES
 *       (lodash.merge, Object.assign, Object.fromEntries, deepmerge, …),
 *       and at least one argument at or after the merge_arg_start index
 *       is structurally user-controlled (a USER_INPUT_RECEIVER_CHAINS
 *       property access, a JSON.parse call, or an identifier that was
 *       initialized from either), emit a PollutionHit.
 *
 *   (b) CRITICAL-KEY WRITE DETECTION — walk every ElementAccessExpression
 *       and PropertyAccessExpression. If the accessed key resolves to one
 *       of CRITICAL_KEY_NAMES (__proto__, constructor, prototype) on an
 *       assignment's LHS, emit a PollutionHit with the literal key
 *       recorded — a direct attacker win that does not need the arg to
 *       be tainted (the code itself is the vulnerability).
 *
 *   (c) DYNAMIC-KEY WRITE WITH USER INPUT — walk ElementAccessExpression
 *       assignments `obj[keyVar] = v`. If `keyVar` is bound to a
 *       user-controlled property chain and no guard function
 *       (hasOwnProperty / Object.create(null) construction target /
 *       allowlist function) is on the path, emit a PollutionHit.
 *
 * Guard detection: if the same AST scope contains a call to one of
 * GUARD_FUNCTION_NAMES whose argument is the same variable name that
 * appears in the sink, or a variable was declared via one of
 * NULL_PROTO_CONSTRUCTOR_PATTERNS, the mitigation is recorded as
 * present.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  MERGE_FUNCTION_NAMES,
  CRITICAL_KEY_NAMES,
  USER_INPUT_RECEIVER_CHAINS,
  GUARD_FUNCTION_NAMES,
  NULL_PROTO_CONSTRUCTOR_PATTERNS,
} from "./data/config.js";

export interface PollutionHit {
  /**
   * Kind of pollution vector:
   *   merge-call       — call to a merge API with tainted input
   *   critical-key     — literal __proto__ / constructor / prototype write
   *   dynamic-key      — obj[tainted] = v write without a guard
   */
  kind: "merge-call" | "critical-key" | "dynamic-key";
  /** Sink location — AST position of the pollution event. */
  sinkLocation: Location;
  /** Source (tainted input) location — may equal sink for literal critical-key writes. */
  sourceLocation: Location;
  /** Rendered sink expression (call text or LHS of assignment). */
  sinkExpression: string;
  /** Rendered source expression (user-input chain, literal key, or tainted binding). */
  sourceExpression: string;
  /** Source category — human-readable. */
  sourceCategory: string;
  /** Guard state — present iff a charter-audited mitigation was observed in scope. */
  guardPresent: boolean;
  /** Guard detail — empty when not present. */
  guardDetail: string;
}

export interface C10GatherResult {
  mode: "absent" | "facts";
  hits: PollutionHit[];
  /** Synthetic filename used for Locations when no source_files map is given. */
  file: string;
}

const SYNTHETIC_FILE = "<source>";

/** Substring markers used to short-circuit on obvious test fixtures. */
const TEST_FILE_SHAPES: readonly string[] = [
  "__tests__",
  ".test.",
  ".spec.",
  "from 'vitest'",
  'from "vitest"',
];

export function gatherC10(context: AnalysisContext): C10GatherResult {
  const source = context.source_code;
  if (!source || source.length === 0) {
    return { mode: "absent", hits: [], file: SYNTHETIC_FILE };
  }
  for (const marker of TEST_FILE_SHAPES) {
    if (source.includes(marker)) {
      return { mode: "absent", hits: [], file: SYNTHETIC_FILE };
    }
  }

  const sf = ts.createSourceFile(
    SYNTHETIC_FILE,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );

  const hits: PollutionHit[] = [];

  // Pass 1 — map every identifier to whether its initializer looked tainted
  // (a user-input receiver chain or a JSON.parse call).
  const taintedBindings = new Set<string>();
  const nullProtoTargets = new Set<string>();
  const guardedBindings = new Set<string>();

  ts.forEachChild(sf, function collect(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const name = node.name.text;
      if (expressionLooksTainted(node.initializer)) {
        taintedBindings.add(name);
      }
      if (initializerIsNullProto(node.initializer)) {
        nullProtoTargets.add(name);
      }
    }
    if (ts.isCallExpression(node)) {
      const call = node;
      const calleeName = getCallName(call);
      if (calleeName && GUARD_FUNCTION_NAMES.includes(calleeName)) {
        for (const arg of call.arguments) {
          if (ts.isIdentifier(arg)) guardedBindings.add(arg.text);
        }
      }
    }
    ts.forEachChild(node, collect);
  });

  // Pass 2 — look for sinks.
  ts.forEachChild(sf, function walk(node) {
    if (ts.isCallExpression(node)) {
      maybeCollectMergeCall(node, sf, hits, taintedBindings, nullProtoTargets, guardedBindings);
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      maybeCollectAssignmentSink(node, sf, hits, taintedBindings, nullProtoTargets, guardedBindings);
    }
    ts.forEachChild(node, walk);
  });

  return { mode: hits.length > 0 ? "facts" : "absent", hits, file: SYNTHETIC_FILE };
}

// ─── Taint shape probes ────────────────────────────────────────────────────

function expressionLooksTainted(expr: ts.Expression): boolean {
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    const chain = renderChain(expr);
    if (chain === null) return false;
    for (const receiver of USER_INPUT_RECEIVER_CHAINS) {
      if (chainStartsWith(chain, receiver)) return true;
    }
    // Recurse into the base — `req.body.x` → `req.body` → `req`.
    return expressionLooksTainted(getBase(expr));
  }
  if (ts.isCallExpression(expr)) {
    const name = getCallName(expr);
    if (name === "parse") {
      // JSON.parse(...) — if the argument references a tainted chain, propagate.
      const arg = expr.arguments[0];
      if (arg && expressionLooksTainted(arg)) return true;
      return false;
    }
    for (const arg of expr.arguments) {
      if (expressionLooksTainted(arg)) return true;
    }
  }
  return false;
}

function initializerIsNullProto(expr: ts.Expression): boolean {
  const rendered = renderExpression(expr);
  for (const pattern of NULL_PROTO_CONSTRUCTOR_PATTERNS) {
    if (rendered.includes(pattern)) return true;
  }
  return false;
}

// ─── Sink collectors ───────────────────────────────────────────────────────

function maybeCollectMergeCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  hits: PollutionHit[],
  taintedBindings: ReadonlySet<string>,
  nullProtoTargets: ReadonlySet<string>,
  guardedBindings: ReadonlySet<string>,
): void {
  const callName = getCallName(call);
  if (callName === null) return;
  const spec = MERGE_FUNCTION_NAMES[callName];
  if (!spec) return;

  // If the MERGE_FUNCTION_NAMES spec says "receivers: ['_', 'lodash']",
  // require the call's receiver to match. Receivers [] means "any" (deepmerge).
  if (spec.receivers.length > 0) {
    const receiver = getCallReceiver(call);
    if (!spec.receivers.includes(receiver ?? "")) return;
  }

  // Look at args from merge_arg_start for tainted input.
  let taintedArg: ts.Expression | null = null;
  for (let i = spec.merge_arg_start; i < call.arguments.length; i++) {
    const arg = call.arguments[i];
    if (isArgumentTainted(arg, taintedBindings)) {
      taintedArg = arg;
      break;
    }
  }
  if (!taintedArg) return;

  // Guard detection — is the target (arg 0 when merge_arg_start > 0)
  // a null-proto object or a guarded binding?
  const targetArg = spec.merge_arg_start > 0 ? call.arguments[0] : null;
  const targetName = targetArg && ts.isIdentifier(targetArg) ? targetArg.text : null;
  const guardPresent =
    (targetName !== null &&
      (nullProtoTargets.has(targetName) || guardedBindings.has(targetName))) ||
    initializerIsNullProto(targetArg ?? call);

  const guardDetail = guardPresent
    ? targetName && nullProtoTargets.has(targetName)
      ? `Merge target "${targetName}" was constructed via Object.create(null) or Map — cannot be polluted.`
      : targetName && guardedBindings.has(targetName)
        ? `Merge target "${targetName}" has a guard call (hasOwnProperty / freeze / seal / allowlistKey / validateKey) in scope.`
        : "A null-proto merge target literal is in play."
    : "";

  hits.push({
    kind: "merge-call",
    sinkLocation: locationOf(sf, call),
    sourceLocation: locationOf(sf, taintedArg),
    sinkExpression: renderNode(call, sf),
    sourceExpression: renderNode(taintedArg, sf),
    sourceCategory: classifyTaintSource(taintedArg),
    guardPresent,
    guardDetail,
  });
}

function maybeCollectAssignmentSink(
  assignment: ts.BinaryExpression,
  sf: ts.SourceFile,
  hits: PollutionHit[],
  taintedBindings: ReadonlySet<string>,
  nullProtoTargets: ReadonlySet<string>,
  guardedBindings: ReadonlySet<string>,
): void {
  const lhs = assignment.left;

  // CASE A — literal critical-key write: obj["__proto__"] = value,
  // or obj.__proto__ = value. The code itself is the vulnerability.
  if (ts.isElementAccessExpression(lhs)) {
    const keyNode = lhs.argumentExpression;
    if (keyNode && (ts.isStringLiteral(keyNode) || ts.isNoSubstitutionTemplateLiteral(keyNode))) {
      if (CRITICAL_KEY_NAMES.includes(keyNode.text)) {
        pushCriticalKeyWrite(assignment, lhs, sf, hits);
        return;
      }
    }
    // CASE B — dynamic-key write where key binding is tainted.
    if (keyNode && ts.isIdentifier(keyNode)) {
      if (taintedBindings.has(keyNode.text)) {
        const targetName = ts.isIdentifier(lhs.expression) ? lhs.expression.text : null;
        const guardPresent =
          (targetName !== null &&
            (nullProtoTargets.has(targetName) || guardedBindings.has(targetName))) ||
          guardedBindings.has(keyNode.text);
        hits.push({
          kind: "dynamic-key",
          sinkLocation: locationOf(sf, assignment),
          sourceLocation: locationOf(sf, keyNode),
          sinkExpression: renderNode(assignment, sf),
          sourceExpression: keyNode.text,
          sourceCategory: "tainted-binding",
          guardPresent,
          guardDetail: guardPresent
            ? `Guard detected: target or key binding is on the charter-audited safe list (${targetName ?? keyNode.text}).`
            : "",
        });
      }
    }
  }
  if (ts.isPropertyAccessExpression(lhs)) {
    if (CRITICAL_KEY_NAMES.includes(lhs.name.text)) {
      pushCriticalKeyWrite(assignment, lhs, sf, hits);
    }
  }
}

function pushCriticalKeyWrite(
  assignment: ts.BinaryExpression,
  lhs: ts.Expression,
  sf: ts.SourceFile,
  hits: PollutionHit[],
): void {
  hits.push({
    kind: "critical-key",
    sinkLocation: locationOf(sf, assignment),
    sourceLocation: locationOf(sf, lhs),
    sinkExpression: renderNode(assignment, sf),
    sourceExpression: renderNode(lhs, sf),
    sourceCategory: "critical-key-write",
    guardPresent: false,
    guardDetail: "",
  });
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function isArgumentTainted(arg: ts.Expression, taintedBindings: ReadonlySet<string>): boolean {
  if (ts.isIdentifier(arg) && taintedBindings.has(arg.text)) return true;
  return expressionLooksTainted(arg);
}

function classifyTaintSource(expr: ts.Expression): string {
  if (ts.isPropertyAccessExpression(expr) || ts.isElementAccessExpression(expr)) {
    const chain = renderChain(expr) ?? [];
    for (const receiver of USER_INPUT_RECEIVER_CHAINS) {
      if (chainStartsWith(chain, receiver)) {
        return receiver.join(".");
      }
    }
  }
  if (ts.isCallExpression(expr)) {
    const name = getCallName(expr);
    if (name === "parse") return "JSON.parse";
  }
  if (ts.isIdentifier(expr)) return `tainted-binding:${expr.text}`;
  return "user-controlled";
}

function chainStartsWith(chain: readonly string[], prefix: readonly string[]): boolean {
  if (chain.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) {
    if (chain[i] !== prefix[i]) return false;
  }
  return true;
}

function renderChain(node: ts.Expression): string[] | null {
  const parts: string[] = [];
  let current: ts.Expression | null = node;
  while (current) {
    if (ts.isPropertyAccessExpression(current)) {
      parts.unshift(current.name.text);
      current = current.expression;
    } else if (ts.isElementAccessExpression(current)) {
      if (ts.isStringLiteral(current.argumentExpression)) {
        parts.unshift(current.argumentExpression.text);
      } else {
        return null;
      }
      current = current.expression;
    } else if (ts.isIdentifier(current)) {
      parts.unshift(current.text);
      return parts;
    } else {
      return null;
    }
  }
  return parts;
}

function getBase(expr: ts.Expression): ts.Expression {
  if (ts.isPropertyAccessExpression(expr)) return expr.expression;
  if (ts.isElementAccessExpression(expr)) return expr.expression;
  return expr;
}

function getCallName(node: ts.CallExpression): string | null {
  if (ts.isIdentifier(node.expression)) return node.expression.text;
  if (ts.isPropertyAccessExpression(node.expression)) return node.expression.name.text;
  return null;
}

function getCallReceiver(node: ts.CallExpression): string | null {
  if (ts.isPropertyAccessExpression(node.expression) && ts.isIdentifier(node.expression.expression)) {
    return node.expression.expression.text;
  }
  return null;
}

function renderNode(node: ts.Node, sf: ts.SourceFile): string {
  const text = node.getText(sf);
  return text.length > 160 ? text.slice(0, 159) + "…" : text;
}

function renderExpression(node: ts.Expression): string {
  const file = node.getSourceFile();
  return file ? node.getText(file) : "";
}

function locationOf(sf: ts.SourceFile, node: ts.Node): Location {
  const start = node.getStart(sf);
  const { line, character } = sf.getLineAndCharacterOfPosition(start);
  return { kind: "source", file: SYNTHETIC_FILE, line: line + 1, col: character + 1 };
}
