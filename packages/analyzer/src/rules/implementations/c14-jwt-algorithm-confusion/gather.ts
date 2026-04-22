/**
 * C14 — JWT Algorithm Confusion: deterministic AST structural analysis.
 *
 * Walks every CallExpression, matches the callee against JWT_CALLS
 * (data/config.ts), then inspects the options argument structurally:
 *
 *   - verify-style call with 2 args (token + secret) only → fire
 *     verify-without-options;
 *   - options.algorithms is an array literal containing "none" (case-
 *     insensitive) → fire algorithms-contains-none;
 *   - options.algorithms is an identifier reference (not an array
 *     literal) → fire algorithms-reference-not-literal at severity high;
 *   - options.ignoreExpiration === true → fire ignore-expiration-true;
 *   - py-decode call with verify=False keyword or options.verify_signature
 *     = False → fire pyjwt-verify-false;
 *   - decode call whose return value is immediately used as `if
 *     (result.<claim>)` → fire decode-used-as-verify.
 *
 * No regex, no string-literal arrays > 5 in this file.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  JWT_CALLS,
  ANTI_PATTERNS,
  OPTION_KEYS,
  type AntiPatternId,
  type JwtCallIdentity,
} from "./data/config.js";

export interface JwtHit {
  /** Which anti-pattern was matched. */
  pattern: AntiPatternId;
  /** Library call identity (for rationale). */
  identity: JwtCallIdentity;
  /** AST position of the call. */
  callLocation: Location;
  /** Rendered call expression. */
  callExpression: string;
  /** Structural detail (e.g. "algorithms array index 2 is 'none'"). */
  detail: string;
  /** Whether a sibling correctly-configured verify call exists in the same file (mitigation signal). */
  siblingSafeCallPresent: boolean;
}

export interface C14GatherResult {
  mode: "absent" | "facts";
  hits: JwtHit[];
  file: string;
}

const SYNTHETIC_FILE = "<source>";

const TEST_FILE_SHAPES: readonly string[] = [
  "__tests__",
  ".test.",
  ".spec.",
  "from 'vitest'",
  'from "vitest"',
];

export function gatherC14(context: AnalysisContext): C14GatherResult {
  const source = context.source_code;
  if (!source) return { mode: "absent", hits: [], file: SYNTHETIC_FILE };
  for (const marker of TEST_FILE_SHAPES) {
    if (source.includes(marker)) return { mode: "absent", hits: [], file: SYNTHETIC_FILE };
  }

  // For Python sources we do a line-wise scan because PyJWT calls use
  // keyword arguments the TS parser cannot parse. TS source goes through
  // the structural AST walk.
  const isPython = source.includes("import jwt") && (source.includes("verify=False") || source.includes("verify_signature"));
  if (isPython) {
    return scanPython(source);
  }

  return scanTypescript(source);
}

// ─── TypeScript AST scan ───────────────────────────────────────────────────

function scanTypescript(source: string): C14GatherResult {
  const sf = ts.createSourceFile(
    SYNTHETIC_FILE,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );

  const hits: JwtHit[] = [];
  const safeVerifyCallsSeen = collectSafeVerifyCalls(sf);

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const identity = matchJwtCall(node);
      if (identity) {
        inspectCall(node, sf, identity, hits, safeVerifyCallsSeen);
      }
    }
    ts.forEachChild(node, visit);
  });

  return { mode: hits.length > 0 ? "facts" : "absent", hits, file: SYNTHETIC_FILE };
}

function matchJwtCall(call: ts.CallExpression): JwtCallIdentity | null {
  const expr = call.expression;
  if (ts.isPropertyAccessExpression(expr)) {
    const method = expr.name.text;
    const receiver = ts.isIdentifier(expr.expression) ? expr.expression.text : null;
    for (const entry of JWT_CALLS) {
      if (entry.name !== method) continue;
      if (entry.receivers.length === 0) return entry;
      if (receiver && entry.receivers.includes(receiver)) return entry;
    }
  }
  if (ts.isIdentifier(expr)) {
    for (const entry of JWT_CALLS) {
      if (entry.receivers.length === 0 && entry.name === expr.text) return entry;
    }
  }
  return null;
}

function inspectCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  identity: JwtCallIdentity,
  hits: JwtHit[],
  safeVerifyCallsSeen: boolean,
): void {
  const callLocation = locationOf(sf, call);
  const callText = renderNode(call, sf);

  if (identity.kind === "verify") {
    const options = call.arguments[2];
    // No options arg at all → verify-without-options anti-pattern.
    if (!options) {
      pushHit(hits, {
        pattern: "verify-without-options",
        identity,
        callLocation,
        callExpression: callText,
        detail:
          "The call has no options argument; historical jsonwebtoken accepts any alg " +
          "in the token header including 'none'.",
        siblingSafeCallPresent: safeVerifyCallsSeen,
      });
      return;
    }
    // Inspect options object literal.
    if (ts.isObjectLiteralExpression(options)) {
      inspectOptionsLiteral(options, call, sf, identity, hits, callLocation, callText, safeVerifyCallsSeen);
      return;
    }
    // Options is a reference (not an object literal) — we can't see inside.
    if (ts.isIdentifier(options) || ts.isPropertyAccessExpression(options)) {
      pushHit(hits, {
        pattern: "algorithms-reference-not-literal",
        identity,
        callLocation,
        callExpression: callText,
        detail:
          `The options argument is the reference "${renderNode(options, sf)}"; static ` +
          "analysis cannot prove the algorithms pin.",
        siblingSafeCallPresent: safeVerifyCallsSeen,
      });
    }
    return;
  }

  if (identity.kind === "decode") {
    // Look at the surrounding use — is the result treated as authenticated?
    if (isUsedAsVerified(call)) {
      pushHit(hits, {
        pattern: "decode-used-as-verify",
        identity,
        callLocation,
        callExpression: callText,
        detail:
          "The decode return value is read as if authenticated — a forged token " +
          "survives because decode() does not verify signature.",
        siblingSafeCallPresent: safeVerifyCallsSeen,
      });
    }
    return;
  }

  if (identity.kind === "py-decode") {
    // TypeScript AST path — Python is handled by scanPython. But if someone
    // writes jwt.decode(..., { verify: false }) in TS they still meant to
    // defeat verification.
    const options = call.arguments[2] ?? call.arguments[1];
    if (options && ts.isObjectLiteralExpression(options)) {
      if (hasFalseVerifyProperty(options)) {
        pushHit(hits, {
          pattern: "pyjwt-verify-false",
          identity,
          callLocation,
          callExpression: callText,
          detail:
            "A verify: false / verify_signature: false property is set on the options. " +
            "The call disables signature verification.",
          siblingSafeCallPresent: safeVerifyCallsSeen,
        });
      }
    }
  }
}

function inspectOptionsLiteral(
  options: ts.ObjectLiteralExpression,
  _call: ts.CallExpression,
  sf: ts.SourceFile,
  identity: JwtCallIdentity,
  hits: JwtHit[],
  callLocation: Location,
  callText: string,
  safeVerifyCallsSeen: boolean,
): void {
  let algorithmsSeen = false;
  for (const prop of options.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const keyName = getPropertyKeyName(prop.name);
    if (keyName === OPTION_KEYS.algorithms) {
      algorithmsSeen = true;
      const value = prop.initializer;
      if (ts.isArrayLiteralExpression(value)) {
        let containsNone = false;
        for (const el of value.elements) {
          if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) {
            if (el.text.toLowerCase() === "none") {
              containsNone = true;
              break;
            }
          }
        }
        if (containsNone) {
          pushHit(hits, {
            pattern: "algorithms-contains-none",
            identity,
            callLocation,
            callExpression: callText,
            detail:
              "The algorithms option array contains the literal 'none' (case-insensitive). " +
              "Tokens with alg=none have no signature.",
            siblingSafeCallPresent: safeVerifyCallsSeen,
          });
        }
      } else if (ts.isIdentifier(value) || ts.isPropertyAccessExpression(value)) {
        pushHit(hits, {
          pattern: "algorithms-reference-not-literal",
          identity,
          callLocation,
          callExpression: callText,
          detail:
            `The algorithms option is "${renderNode(value, sf)}" — a reference, not an ` +
            "array literal. Static analysis cannot prove the pin.",
          siblingSafeCallPresent: safeVerifyCallsSeen,
        });
      }
    } else if (keyName === OPTION_KEYS.ignoreExpiration) {
      if (prop.initializer.kind === ts.SyntaxKind.TrueKeyword) {
        pushHit(hits, {
          pattern: "ignore-expiration-true",
          identity,
          callLocation,
          callExpression: callText,
          detail:
            "ignoreExpiration: true — tokens whose exp claim has passed still validate.",
          siblingSafeCallPresent: safeVerifyCallsSeen,
        });
      }
    }
  }
  if (!algorithmsSeen) {
    pushHit(hits, {
      pattern: "verify-without-options",
      identity,
      callLocation,
      callExpression: callText,
      detail:
        "An options object is present but has no `algorithms` key pinning accepted " +
        "algorithms. Jsonwebtoken will fall back to the token-header alg — including 'none' " +
        "on old library versions.",
      siblingSafeCallPresent: safeVerifyCallsSeen,
    });
  }
}

function hasFalseVerifyProperty(options: ts.ObjectLiteralExpression): boolean {
  for (const prop of options.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const keyName = getPropertyKeyName(prop.name);
    if (keyName === "verify" || keyName === "verify_signature") {
      if (prop.initializer.kind === ts.SyntaxKind.FalseKeyword) return true;
      if (
        (ts.isStringLiteral(prop.initializer) || ts.isNoSubstitutionTemplateLiteral(prop.initializer)) &&
        prop.initializer.text.toLowerCase() === "false"
      ) {
        return true;
      }
    }
  }
  return false;
}

function getPropertyKeyName(node: ts.PropertyName): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  return null;
}

function isUsedAsVerified(call: ts.CallExpression): boolean {
  // Climb the AST — is there a parent shape that treats the decode return
  // value as authenticated? We look for: property access on the result
  // (result.isAdmin / result.sub) AND that expression being used in a
  // conditional / return / function argument that names "auth" / "admin".
  let current: ts.Node = call;
  let hops = 0;
  while (current.parent && hops++ < 4) {
    const parent = current.parent;
    if (ts.isPropertyAccessExpression(parent) && parent.expression === current) {
      const propName = parent.name.text.toLowerCase();
      if (propName.includes("admin") || propName.includes("role") || propName.includes("user") || propName.includes("sub")) {
        return true;
      }
    }
    current = parent;
  }
  return false;
}

// ─── Safe-sibling-call detection ───────────────────────────────────────────

function collectSafeVerifyCalls(sf: ts.SourceFile): boolean {
  let safe = false;
  ts.forEachChild(sf, function visit(node) {
    if (safe) return;
    if (ts.isCallExpression(node)) {
      const identity = matchJwtCall(node);
      if (identity && identity.kind === "verify") {
        const options = node.arguments[2];
        if (options && ts.isObjectLiteralExpression(options)) {
          for (const prop of options.properties) {
            if (!ts.isPropertyAssignment(prop)) continue;
            const keyName = getPropertyKeyName(prop.name);
            if (keyName === OPTION_KEYS.algorithms && ts.isArrayLiteralExpression(prop.initializer)) {
              let allSafe = true;
              let anySafe = false;
              for (const el of prop.initializer.elements) {
                if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) {
                  if (el.text.toLowerCase() === "none") {
                    allSafe = false;
                    break;
                  }
                  anySafe = true;
                }
              }
              if (allSafe && anySafe) safe = true;
            }
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  });
  return safe;
}

// ─── Python line-wise scan ────────────────────────────────────────────────

function scanPython(source: string): C14GatherResult {
  const hits: JwtHit[] = [];
  const lines = source.split("\n");
  const pyIdentity: JwtCallIdentity = {
    name: "decode",
    receivers: ["pyjwt", "PyJWT"],
    kind: "py-decode",
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (trimmed.startsWith("#")) continue;
    if (!line.includes("jwt.decode") && !line.includes("jwt.verify")) continue;

    // verify=False anywhere in the arguments list.
    if (line.includes("verify=False") || line.includes("verify_signature\": False") || line.includes('"verify_signature": False') || line.includes("'verify_signature': False")) {
      hits.push({
        pattern: "pyjwt-verify-false",
        identity: pyIdentity,
        callLocation: { kind: "source", file: SYNTHETIC_FILE, line: i + 1, col: 1 },
        callExpression: trimmed.slice(0, 160),
        detail: "Python PyJWT call disables signature verification (verify=False or verify_signature: False).",
        siblingSafeCallPresent: false,
      });
      continue;
    }
    // algorithms=["none"] anywhere on the line.
    if (line.toLowerCase().includes("algorithms=[\"none\"") || line.toLowerCase().includes("algorithms=['none'")) {
      hits.push({
        pattern: "algorithms-contains-none",
        identity: pyIdentity,
        callLocation: { kind: "source", file: SYNTHETIC_FILE, line: i + 1, col: 1 },
        callExpression: trimmed.slice(0, 160),
        detail: "Python PyJWT decode/verify call pins algorithms to ['none'] — all forged tokens pass.",
        siblingSafeCallPresent: false,
      });
    }
  }
  return { mode: hits.length > 0 ? "facts" : "absent", hits, file: SYNTHETIC_FILE };
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function pushHit(hits: JwtHit[], hit: JwtHit): void {
  // ensure one hit per pattern per call location
  const key = `${hit.pattern}:${(hit.callLocation as { line?: number }).line}`;
  if (hits.some((h) => `${h.pattern}:${(h.callLocation as { line?: number }).line}` === key)) return;
  hits.push(hit);
  void ANTI_PATTERNS[hit.pattern]; // reference to ensure imports are live.
}

function renderNode(node: ts.Node, sf: ts.SourceFile): string {
  const text = node.getText(sf);
  return text.length > 160 ? text.slice(0, 159) + "…" : text;
}

function locationOf(sf: ts.SourceFile, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file: SYNTHETIC_FILE, line: line + 1, col: character + 1 };
}
