/**
 * K7 AST walker — token-creation calls + expiry-property assignments.
 *
 * Zero regex. Duration parsing is a manual character scan; threshold
 * comparisons are purely numeric.
 */

import ts from "typescript";
import type { Location } from "../../location.js";
import {
  TOKEN_METHODS,
  TOKEN_RECEIVERS,
  BARE_TOKEN_CREATION_CALLS,
} from "./data/token-libraries.js";
import {
  EXPIRY_DURATION_PROPERTIES,
  EXPIRY_DISABLE_PROPERTIES,
  DURATION_UNIT_SECONDS,
  MS_SUFFIXES,
  MAX_ACCESS_TOKEN_SECONDS,
  MAX_REFRESH_TOKEN_SECONDS,
} from "./data/expiry-properties.js";
import type {
  FileEvidence,
  K7Site,
  TokenCreationSite,
  ExpiryAssignmentSite,
  ExpiryFindingKind,
} from "./gather.js";

const TOKEN_METHOD_SET: ReadonlySet<string> = new Set(Object.keys(TOKEN_METHODS));
const TOKEN_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(TOKEN_RECEIVERS));
const BARE_TOKEN_CALL_SET: ReadonlySet<string> = new Set(Object.keys(BARE_TOKEN_CREATION_CALLS));
const EXPIRY_DURATION_SET: ReadonlySet<string> = new Set(Object.keys(EXPIRY_DURATION_PROPERTIES));
const MS_SUFFIX_SET: ReadonlySet<string> = new Set(Object.keys(MS_SUFFIXES));

const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set([
  "vitest", "jest", "@jest/globals", "mocha", "node:test",
]);
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set([
  "describe", "it", "test", "suite",
]);

export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  const sites: K7Site[] = [];

  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      const creation = inspectTokenCreation(node, sf, file);
      if (creation) sites.push(creation);

      const propAssign = inspectExpiryPropertyAssignment(node, sf, file);
      if (propAssign) sites.push(propAssign);

      ts.forEachChild(node, visit);
    });
  }

  return { file, sites, isTestFile };
}

// ─── Test-file structural detection ────────────────────────────────────────

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_RUNNER_MODULE_SET.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee) && TEST_TOPLEVEL_SET.has(callee.text)) {
        for (const arg of stmt.expression.arguments) {
          if (ts.isArrowFunction(arg) || ts.isFunctionExpression(arg)) {
            topLevelRunnerCalls++;
            break;
          }
        }
      }
    }
  }
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
}

// ─── Token-creation call inspection ────────────────────────────────────────

function inspectTokenCreation(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): TokenCreationSite | null {
  if (!ts.isCallExpression(node)) return null;
  const label = classifyTokenCallCallee(node.expression);
  if (!label) return null;

  const loc = sourceLocation(sf, file, node);
  const observed = lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200);

  // Options object is conventionally the LAST argument in JS token libraries
  // (jwt.sign(payload, secret, options), mintJwt(payload, options), etc.).
  // Picking the first ObjectLiteralExpression would incorrectly match the
  // payload object in `jwt.sign({ userId }, "secret", { expiresIn: "1h" })`.
  const lastArg = node.arguments[node.arguments.length - 1];
  const optionsObject =
    lastArg && ts.isObjectLiteralExpression(lastArg) ? lastArg : null;

  const isRefreshToken = label.toLowerCase().includes("refresh") || argListMentionsRefresh(node, sf);

  if (!optionsObject) {
    // No options object → no expiry set.
    return {
      kind: "token-creation",
      location: loc,
      callerLabel: label,
      findingKind: "no-expiry",
      durationSeconds: null,
      observed,
      durationJsonPointer: null,
      isRefreshToken,
    };
  }

  const expiryEval = evaluateOptionsForExpiry(optionsObject);
  if (expiryEval.kind === "no-property") {
    return {
      kind: "token-creation",
      location: loc,
      callerLabel: label,
      findingKind: "no-expiry",
      durationSeconds: null,
      observed,
      durationJsonPointer: null,
      isRefreshToken,
    };
  }
  if (expiryEval.kind === "disabled") {
    return {
      kind: "token-creation",
      location: loc,
      callerLabel: label,
      findingKind: "disabled-expiry",
      durationSeconds: null,
      observed,
      durationJsonPointer: expiryEval.jsonPointer,
      isRefreshToken,
    };
  }
  if (expiryEval.kind === "excessive") {
    const threshold = isRefreshToken ? MAX_REFRESH_TOKEN_SECONDS : MAX_ACCESS_TOKEN_SECONDS;
    if (expiryEval.seconds > threshold) {
      return {
        kind: "token-creation",
        location: loc,
        callerLabel: label,
        findingKind: isRefreshToken ? "excessive-expiry-refresh" : "excessive-expiry",
        durationSeconds: expiryEval.seconds,
        observed,
        durationJsonPointer: expiryEval.jsonPointer,
        isRefreshToken,
      };
    }
  }
  return null;
}

function classifyTokenCallCallee(callee: ts.Expression): string | null {
  if (ts.isPropertyAccessExpression(callee)) {
    const method = callee.name.text.toLowerCase();
    if (!TOKEN_METHOD_SET.has(method)) return null;
    const receiverLabel = receiverText(callee.expression);
    if (!receiverLabel) return null;
    if (!TOKEN_RECEIVER_SET.has(receiverLabel.toLowerCase())) return null;
    return `${receiverLabel}.${callee.name.text}`;
  }
  if (ts.isIdentifier(callee)) {
    const name = callee.text.toLowerCase();
    if (BARE_TOKEN_CALL_SET.has(name)) return callee.text;
    return null;
  }
  return null;
}

function receiverText(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
  return null;
}

function argListMentionsRefresh(call: ts.CallExpression, sf: ts.SourceFile): boolean {
  for (const arg of call.arguments) {
    const txt = arg.getText(sf).toLowerCase();
    if (txt.includes("refresh")) return true;
  }
  return false;
}

// ─── Options-object expiry evaluation ──────────────────────────────────────

type ExpiryEvaluation =
  | { kind: "no-property" }
  | { kind: "disabled"; jsonPointer: string }
  | { kind: "excessive"; seconds: number; jsonPointer: string }
  | { kind: "acceptable"; seconds: number; jsonPointer: string };

function evaluateOptionsForExpiry(obj: ts.ObjectLiteralExpression): ExpiryEvaluation {
  let found: ExpiryEvaluation = { kind: "no-property" };
  for (const prop of obj.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const name = propertyNameText(prop.name);
    if (!name) continue;
    const lower = name.toLowerCase();

    // Disable-path first — "ignoreExpiration: true" should win even if a duration exists elsewhere.
    const disableMode = EXPIRY_DISABLE_PROPERTIES[lower];
    if (disableMode && isDisablingLiteral(prop.initializer, disableMode)) {
      return { kind: "disabled", jsonPointer: `/${escapePointerSegment(name)}` };
    }

    if (EXPIRY_DURATION_SET.has(lower)) {
      const sec = extractDurationSeconds(prop.initializer);
      if (sec === null) {
        // Present but unresolvable (computed expression).
        found = { kind: "acceptable", seconds: 0, jsonPointer: `/${escapePointerSegment(name)}` };
        continue;
      }
      if (sec > MAX_ACCESS_TOKEN_SECONDS) {
        found = { kind: "excessive", seconds: sec, jsonPointer: `/${escapePointerSegment(name)}` };
      } else {
        return { kind: "acceptable", seconds: sec, jsonPointer: `/${escapePointerSegment(name)}` };
      }
    }
  }
  return found;
}

function isDisablingLiteral(expr: ts.Expression, mode: "true" | "false" | "zero-or-null"): boolean {
  if (mode === "true") {
    return expr.kind === ts.SyntaxKind.TrueKeyword;
  }
  if (mode === "false") {
    return expr.kind === ts.SyntaxKind.FalseKeyword;
  }
  // zero-or-null: numeric 0, null, undefined identifier.
  if (ts.isNumericLiteral(expr) && expr.text === "0") return true;
  if (expr.kind === ts.SyntaxKind.NullKeyword) return true;
  if (ts.isIdentifier(expr) && expr.text === "undefined") return true;
  return false;
}

// ─── Expiry-property-only assignment inspection ────────────────────────────

function inspectExpiryPropertyAssignment(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
): ExpiryAssignmentSite | null {
  // Property-assignment in an object literal.
  if (ts.isPropertyAssignment(node)) {
    // Skip when the property lives inside an options object that's the
    // argument of a token-creation call — the inspectTokenCreation path
    // handles those end-to-end (with refresh-context classification).
    // Emitting here would produce a false positive using the access-class
    // threshold even when the call is a refresh-token issuance.
    if (isInsideTokenCreationOptions(node)) return null;
    const name = propertyNameText(node.name);
    if (!name) return null;
    const lower = name.toLowerCase();
    if (!EXPIRY_DURATION_SET.has(lower) && !(lower in EXPIRY_DISABLE_PROPERTIES)) return null;

    // Disable path.
    const disableMode = EXPIRY_DISABLE_PROPERTIES[lower];
    if (disableMode && isDisablingLiteral(node.initializer, disableMode)) {
      return {
        kind: "expiry-assignment",
        location: sourceLocation(sf, file, node),
        propertyName: name,
        findingKind: "disabled-expiry",
        durationSeconds: null,
        observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
        isRefreshToken: lower.includes("refresh"),
      };
    }

    if (EXPIRY_DURATION_SET.has(lower)) {
      const sec = extractDurationSeconds(node.initializer);
      if (sec !== null) {
        const threshold = lower.includes("refresh")
          ? MAX_REFRESH_TOKEN_SECONDS
          : MAX_ACCESS_TOKEN_SECONDS;
        if (sec > threshold) {
          return {
            kind: "expiry-assignment",
            location: sourceLocation(sf, file, node),
            propertyName: name,
            findingKind: lower.includes("refresh") ? "excessive-expiry-refresh" : "excessive-expiry",
            durationSeconds: sec,
            observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
            isRefreshToken: lower.includes("refresh"),
          };
        }
      }
    }
  }
  return null;
}

/**
 * True when `prop` is inside an ObjectLiteralExpression that is the
 * argument of a CallExpression whose callee resolves to a known
 * token-creation call. Used by inspectExpiryPropertyAssignment to avoid
 * double-firing on properties the token-creation path already evaluated.
 */
function isInsideTokenCreationOptions(prop: ts.PropertyAssignment): boolean {
  const obj = prop.parent;
  if (!obj || !ts.isObjectLiteralExpression(obj)) return false;
  const call = obj.parent;
  if (!call || !ts.isCallExpression(call)) return false;
  return classifyTokenCallCallee(call.expression) !== null;
}

// ─── Duration parsing ──────────────────────────────────────────────────────

/**
 * Convert a numeric or string literal expression into a duration in
 * seconds. Recognised forms:
 *
 *   - NumericLiteral: 86400 → 86400 seconds
 *   - StringLiteral or NoSubstitutionTemplate: "365d", "24h", "1y",
 *     "86400", "1000000ms"
 *
 * Returns null when the expression is not a parseable literal (e.g. a
 * computed expression or an identifier reference).
 */
function extractDurationSeconds(expr: ts.Expression): number | null {
  if (ts.isNumericLiteral(expr)) {
    const n = Number(expr.text);
    return Number.isFinite(n) ? n : null;
  }
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return parseDurationString(expr.text.trim());
  }
  return null;
}

export function parseDurationString(raw: string): number | null {
  const s = raw.trim();
  if (s.length === 0) return null;

  // Split into numeric prefix + unit suffix (character scan, no regex).
  let i = 0;
  while (i < s.length) {
    const ch = s[i];
    if (!((ch >= "0" && ch <= "9") || ch === ".")) break;
    i++;
  }
  if (i === 0) return null;
  const numPart = s.slice(0, i);
  const unit = s.slice(i).toLowerCase();
  const n = Number(numPart);
  if (!Number.isFinite(n)) return null;

  if (unit === "") return n; // Bare number = seconds
  if (MS_SUFFIX_SET.has(unit)) return n / 1000;
  const mult = DURATION_UNIT_SECONDS[unit];
  if (mult === undefined) return null;
  return n * mult;
}

// ─── AST helpers ───────────────────────────────────────────────────────────

function propertyNameText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) return name.text;
  return null;
}

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  const lines = sf.text.split("\n");
  return lines[line] ?? "";
}

function escapePointerSegment(seg: string): string {
  let out = "";
  for (const ch of seg) {
    if (ch === "~") out += "~0";
    else if (ch === "/") out += "~1";
    else out += ch;
  }
  return out;
}
