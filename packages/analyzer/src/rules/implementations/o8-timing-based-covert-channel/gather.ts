/**
 * O8 gather — AST walk for timing primitives whose delay argument
 * is data-dependent (i.e. NOT a numeric literal and NOT a known
 * counter/constant identifier).
 *
 * Zero regex. Matches five structural shapes:
 *
 *   1. `setTimeout(cb, <arg>)` / `setImmediate(cb, <arg>)` /
 *      `setInterval(cb, <arg>)` — `<arg>` must be non-literal and
 *      not a counter identifier.
 *   2. `await new Promise(r => setTimeout(r, <arg>))`.
 *   3. `sleep(<arg>)` / `time.sleep(<arg>)` / `asyncio.sleep(<arg>)`.
 *   4. `res.setHeader("Retry-After", <arg>)` / `reply.header(...)`
 *      / `res.set(...)` where the header key is the literal
 *      "Retry-After" and the value is non-constant.
 *   5. `sendProgress(...)` / `progress(...)` sandwiching a
 *      non-constant sleep — the interval itself carries the
 *      covert payload.
 *
 * Honest-refusal gate: if the source contains zero timing
 * primitives at all (no setTimeout / sleep / setImmediate /
 * setInterval / performance.now), the gather returns early.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  TIMING_CALL_PRIMITIVES,
  COUNTER_IDENTIFIERS,
  DATA_DEPENDENT_HINTS,
  RETRY_AFTER_SETTERS,
  PROGRESS_NOTIFIERS,
} from "./data/timing-primitives.js";

const TIMING_CALL_SET: ReadonlySet<string> = new Set(
  Object.keys(TIMING_CALL_PRIMITIVES).map((k) => k.split(".").pop() as string),
);
const COUNTER_SET: ReadonlySet<string> = new Set(
  Object.keys(COUNTER_IDENTIFIERS).map((k) => k.toLowerCase()),
);
const DATA_HINT_SET: ReadonlySet<string> = new Set(
  Object.keys(DATA_DEPENDENT_HINTS).map((k) => k.toLowerCase()),
);
const RETRY_SETTER_SET: ReadonlySet<string> = new Set(
  Object.keys(RETRY_AFTER_SETTERS),
);
const PROGRESS_SET: ReadonlySet<string> = new Set(
  Object.keys(PROGRESS_NOTIFIERS),
);

export type TimingShape =
  | "set-timeout-call"
  | "promise-settimeout"
  | "sleep-call"
  | "retry-after-header"
  | "progress-interval-modulation";

export interface TimingSite {
  shape: TimingShape;
  /** Primitive identifier observed (e.g. "setTimeout", "sleep"). */
  primitive: string;
  /** Verbatim delay expression (truncated). */
  delayExpression: string;
  /** Identifier text read by the delay expression (first one), or null. */
  delayReadsIdentifier: string | null;
  /** One of the data-dependent-hint names matched the delay read. */
  matchedDataHint: string | null;
  /** Delay expression reads no counter/constant identifier name. */
  noCounterIdentifier: boolean;
  /** Delay is an obvious numeric literal — causes the site to be dropped. */
  isNumericLiteral: boolean;
  /** Location of the timing primitive. */
  location: Location;
  /** Enclosing function Location, or null. */
  enclosingFunctionLocation: Location | null;
}

export interface O8Gathered {
  sites: TimingSite[];
  hasTimingPrimitive: boolean;
}

export function gatherO8(context: AnalysisContext): O8Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], hasTimingPrimitive: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  // Honest-refusal gate: cheap token pre-scan.
  const hasTimingPrimitive = containsTimingPrimitive(sf);
  if (!hasTimingPrimitive) return { sites: [], hasTimingPrimitive: false };

  const sites: TimingSite[] = [];
  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      collectSetTimeoutLike(node, sf, sites);
      collectSleepLike(node, sf, sites);
      collectRetryAfterHeader(node, sf, sites);
      collectProgressIntervalModulation(node, sf, sites);
    }
    ts.forEachChild(node, visit);
  });

  return { sites, hasTimingPrimitive: true };
}

function containsTimingPrimitive(sf: ts.SourceFile): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && TIMING_CALL_SET.has(n.text)) {
      found = true;
      return;
    }
    if (ts.isPropertyAccessExpression(n)) {
      const name = n.name.text;
      if (TIMING_CALL_SET.has(name)) {
        found = true;
        return;
      }
      // performance.now() primitive presence
      if (ts.isIdentifier(n.expression) && n.expression.text === "performance" && name === "now") {
        found = true;
        return;
      }
    }
    // Retry-After header setting is also a timing primitive: the header carries
    // a delay value the caller reads and waits on.
    if (ts.isStringLiteral(n) && n.text.toLowerCase() === "retry-after") {
      found = true;
      return;
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(sf, visit);
  return found;
}

function collectSetTimeoutLike(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  out: TimingSite[],
): void {
  // Shape 1: setTimeout / setImmediate / setInterval as a bare Identifier
  if (ts.isIdentifier(call.expression)) {
    const name = call.expression.text;
    if (!TIMING_CALL_SET.has(name)) return;
    if (name === "sleep") return; // handled by collectSleepLike
    // setTimeout(cb, delay) — delay is second arg. setImmediate has no delay.
    const delayArg = call.arguments[1];
    if (!delayArg) return;
    const { reads, matchedHint, isLiteral, noCounter } = classifyDelayArg(delayArg);
    if (isLiteral || !noCounter) return; // skip literal + counter-driven
    const timingShape: TimingShape = name === "setTimeout" ? "set-timeout-call"
      : name === "setInterval" ? "set-timeout-call"
      : "set-timeout-call";
    out.push({
      shape: timingShape,
      primitive: name,
      delayExpression: truncate(delayArg.getText(sf), 200),
      delayReadsIdentifier: reads,
      matchedDataHint: matchedHint,
      noCounterIdentifier: noCounter,
      isNumericLiteral: isLiteral,
      location: sourceLocation(sf, call),
      enclosingFunctionLocation: locationOfEnclosingFunction(call, sf),
    });
    return;
  }
  // Shape 2: `new Promise(r => setTimeout(r, <arg>))` inline — the outer call is
  // a Promise constructor; we pick the inner setTimeout separately.
}

function collectSleepLike(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  out: TimingSite[],
): void {
  // sleep(arg) bare identifier
  if (ts.isIdentifier(call.expression) && call.expression.text === "sleep") {
    const arg = call.arguments[0];
    if (!arg) return;
    const { reads, matchedHint, isLiteral, noCounter } = classifyDelayArg(arg);
    if (isLiteral || !noCounter) return;
    out.push({
      shape: "sleep-call",
      primitive: "sleep",
      delayExpression: truncate(arg.getText(sf), 200),
      delayReadsIdentifier: reads,
      matchedDataHint: matchedHint,
      noCounterIdentifier: noCounter,
      isNumericLiteral: isLiteral,
      location: sourceLocation(sf, call),
      enclosingFunctionLocation: locationOfEnclosingFunction(call, sf),
    });
    return;
  }
  // time.sleep(arg) / asyncio.sleep(arg)
  if (ts.isPropertyAccessExpression(call.expression) && call.expression.name.text === "sleep") {
    const arg = call.arguments[0];
    if (!arg) return;
    const { reads, matchedHint, isLiteral, noCounter } = classifyDelayArg(arg);
    if (isLiteral || !noCounter) return;
    const recv = call.expression.expression.getText(sf);
    out.push({
      shape: "sleep-call",
      primitive: `${recv}.sleep`,
      delayExpression: truncate(arg.getText(sf), 200),
      delayReadsIdentifier: reads,
      matchedDataHint: matchedHint,
      noCounterIdentifier: noCounter,
      isNumericLiteral: isLiteral,
      location: sourceLocation(sf, call),
      enclosingFunctionLocation: locationOfEnclosingFunction(call, sf),
    });
  }
}

function collectRetryAfterHeader(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  out: TimingSite[],
): void {
  if (!ts.isPropertyAccessExpression(call.expression)) return;
  const method = call.expression.name.text;
  if (!RETRY_SETTER_SET.has(method)) return;
  // First arg = header name (expect "Retry-After"); second arg = value.
  const [keyArg, valArg] = call.arguments;
  if (!keyArg || !valArg) return;
  if (!ts.isStringLiteral(keyArg)) return;
  if (keyArg.text.toLowerCase() !== "retry-after") return;
  const { reads, matchedHint, isLiteral, noCounter } = classifyDelayArg(valArg);
  if (isLiteral || !noCounter) return;
  out.push({
    shape: "retry-after-header",
    primitive: `${call.expression.expression.getText(sf)}.${method}`,
    delayExpression: truncate(valArg.getText(sf), 200),
    delayReadsIdentifier: reads,
    matchedDataHint: matchedHint,
    noCounterIdentifier: noCounter,
    isNumericLiteral: isLiteral,
    location: sourceLocation(sf, call),
    enclosingFunctionLocation: locationOfEnclosingFunction(call, sf),
  });
}

function collectProgressIntervalModulation(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  out: TimingSite[],
): void {
  // Detect sendProgress(...) call whose enclosing block also contains a
  // non-constant sleep. One emission per enclosing function.
  let name: string | null = null;
  if (ts.isIdentifier(call.expression) && PROGRESS_SET.has(call.expression.text)) {
    name = call.expression.text;
  } else if (
    ts.isPropertyAccessExpression(call.expression) &&
    PROGRESS_SET.has(call.expression.name.text)
  ) {
    name = call.expression.name.text;
  }
  if (!name) return;
  const block = findEnclosingBlock(call);
  if (!block) return;
  const hasVarDelay = blockHasVariableDelay(block, sf);
  if (!hasVarDelay) return;
  out.push({
    shape: "progress-interval-modulation",
    primitive: name,
    delayExpression: truncate(call.getText(sf), 200),
    delayReadsIdentifier: null,
    matchedDataHint: null,
    noCounterIdentifier: true,
    isNumericLiteral: false,
    location: sourceLocation(sf, call),
    enclosingFunctionLocation: locationOfEnclosingFunction(call, sf),
  });
}

interface DelayClassification {
  reads: string | null;
  matchedHint: string | null;
  isLiteral: boolean;
  noCounter: boolean;
}

function classifyDelayArg(arg: ts.Expression): DelayClassification {
  if (ts.isNumericLiteral(arg)) {
    return { reads: null, matchedHint: null, isLiteral: true, noCounter: true };
  }
  let firstIdent: string | null = null;
  let hasCounter = false;
  let matchedHint: string | null = null;
  function visit(n: ts.Node): void {
    if (ts.isIdentifier(n)) {
      const lowered = n.text.toLowerCase();
      if (firstIdent === null) firstIdent = n.text;
      if (COUNTER_SET.has(lowered)) hasCounter = true;
      if (matchedHint === null && DATA_HINT_SET.has(lowered)) matchedHint = n.text;
    }
    ts.forEachChild(n, visit);
  }
  visit(arg);
  return {
    reads: firstIdent,
    matchedHint,
    isLiteral: false,
    noCounter: !hasCounter,
  };
}

function findEnclosingBlock(node: ts.Node): ts.Block | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (ts.isBlock(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

function blockHasVariableDelay(block: ts.Block, sf: ts.SourceFile): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isCallExpression(n)) {
      const name = callName(n);
      if (name === "setTimeout" || name === "sleep" || name === "setInterval") {
        const arg = name === "setTimeout" ? n.arguments[1] : n.arguments[0];
        if (arg && !ts.isNumericLiteral(arg)) {
          const { noCounter } = classifyDelayArg(arg);
          if (noCounter) {
            found = true;
            return;
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(block);
  return found;
}

function callName(call: ts.CallExpression): string | null {
  if (ts.isIdentifier(call.expression)) return call.expression.text;
  if (ts.isPropertyAccessExpression(call.expression)) return call.expression.name.text;
  return null;
}

function locationOfEnclosingFunction(
  node: ts.Node,
  sf: ts.SourceFile,
): Location | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur)
    ) {
      return sourceLocation(sf, cur);
    }
    cur = cur.parent;
  }
  return null;
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

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max) + "…";
}
