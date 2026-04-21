/**
 * K6 AST walker — source-code surface.
 *
 * Walks the TypeScript AST, finds every OAuth scope assignment, and
 * classifies the scope values via structural + vocabulary checks. Zero
 * regex; zero string-literal arrays > 5.
 *
 * The walker recognises four assignment patterns:
 *
 *   1. `scope: "admin"` / `scopes: [...]` inside an ObjectLiteralExpression
 *   2. `config.scope = "*"` binary assignment
 *   3. `const scope = "read:all"` variable declaration with matching name
 *   4. function-call property-arg: `oauth.configure({ scope: "..." })` —
 *      handled implicitly by (1), since (1) walks every ObjectLiteralExpression.
 */

import ts from "typescript";
import type { Location } from "../../location.js";
import {
  WILDCARD_TOKENS,
  ADMIN_TOKENS,
  BROAD_PREFIXED_TOKENS,
  ADMIN_SUFFIX_SEGMENTS,
  WILDCARD_SUFFIX_SEGMENTS,
  type ScopeSeverity,
} from "./data/broad-scopes.js";
import {
  OAUTH_SCOPE_PROPERTY_NAMES,
  AMBIGUOUS_SCOPE_PROPERTY_NAMES,
  OAUTH_CONTEXT_KEYS,
} from "./data/scope-properties.js";
import {
  USER_INPUT_IDENTIFIERS,
  USER_INPUT_RECEIVER_ROOTS,
  USER_INPUT_CHAIN_MARKERS,
} from "./data/user-input-sources.js";
import type {
  FileEvidence,
  ScopeAssignment,
  ScopeMatch,
} from "./gather.js";

const OAUTH_SCOPE_NAME_SET: ReadonlySet<string> = new Set(Object.keys(OAUTH_SCOPE_PROPERTY_NAMES));
const AMBIGUOUS_SCOPE_NAME_SET: ReadonlySet<string> = new Set(Object.keys(AMBIGUOUS_SCOPE_PROPERTY_NAMES));
const OAUTH_CONTEXT_KEY_SET: ReadonlySet<string> = new Set(Object.keys(OAUTH_CONTEXT_KEYS));
const WILDCARD_TOKEN_SET: ReadonlySet<string> = new Set(Object.keys(WILDCARD_TOKENS));
const ADMIN_TOKEN_SET: ReadonlySet<string> = new Set(Object.keys(ADMIN_TOKENS));
const BROAD_PREFIXED_TOKEN_SET: ReadonlySet<string> = new Set(Object.keys(BROAD_PREFIXED_TOKENS));
const ADMIN_SUFFIX_SET: ReadonlySet<string> = new Set(Object.keys(ADMIN_SUFFIX_SEGMENTS));
const WILDCARD_SUFFIX_SET: ReadonlySet<string> = new Set(Object.keys(WILDCARD_SUFFIX_SEGMENTS));
const USER_INPUT_IDENTIFIER_SET: ReadonlySet<string> = new Set(Object.keys(USER_INPUT_IDENTIFIERS));
const USER_INPUT_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(USER_INPUT_RECEIVER_ROOTS));
const USER_INPUT_CHAIN_SET: ReadonlySet<string> = new Set(Object.keys(USER_INPUT_CHAIN_MARKERS));

const TEST_RUNNER_MODULE_SET: ReadonlySet<string> = new Set([
  "vitest",
  "jest",
  "@jest/globals",
  "mocha",
  "node:test",
]);
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set([
  "describe",
  "it",
  "test",
  "suite",
]);

// ─── Entry point ───────────────────────────────────────────────────────────

export function gatherFile(file: string, text: string): FileEvidence {
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileStructurally(sf);
  const assignments: ScopeAssignment[] = [];

  if (!isTestFile) {
    ts.forEachChild(sf, function visit(node) {
      collectFromPropertyAssignment(node, sf, file, assignments);
      collectFromBinaryAssignment(node, sf, file, assignments);
      collectFromVariableDecl(node, sf, file, assignments);
      ts.forEachChild(node, visit);
    });
  }

  return { file, assignments, isTestFile };
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

// ─── Assignment collectors ─────────────────────────────────────────────────

function collectFromPropertyAssignment(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  out: ScopeAssignment[],
): void {
  if (!ts.isPropertyAssignment(node)) return;
  const name = propertyNameText(node.name);
  if (!name) return;
  const nameLower = name.toLowerCase();

  const oauthScopeHit = OAUTH_SCOPE_NAME_SET.has(nameLower);
  const ambiguousHit = AMBIGUOUS_SCOPE_NAME_SET.has(nameLower);
  if (!oauthScopeHit && !ambiguousHit) return;

  const matchedViaOAuthContext = !oauthScopeHit && ambiguousHit
    ? enclosingObjectHasOAuthContext(node)
    : false;
  if (!oauthScopeHit && !matchedViaOAuthContext) return;

  const assignment = buildAssignment(
    name,
    matchedViaOAuthContext,
    node,
    node.initializer,
    sf,
    file,
  );
  if (assignment) out.push(assignment);
}

function collectFromBinaryAssignment(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  out: ScopeAssignment[],
): void {
  if (!ts.isBinaryExpression(node)) return;
  if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
  const leftTail = tailIdentifierOfExpression(node.left);
  if (!leftTail) return;
  const lower = leftTail.toLowerCase();
  if (!OAUTH_SCOPE_NAME_SET.has(lower)) return;

  const assignment = buildAssignment(
    leftTail,
    false,
    node,
    node.right,
    sf,
    file,
  );
  if (assignment) out.push(assignment);
}

function collectFromVariableDecl(
  node: ts.Node,
  sf: ts.SourceFile,
  file: string,
  out: ScopeAssignment[],
): void {
  if (!ts.isVariableDeclaration(node)) return;
  if (!ts.isIdentifier(node.name)) return;
  if (!node.initializer) return;
  const lower = node.name.text.toLowerCase();
  if (!OAUTH_SCOPE_NAME_SET.has(lower)) return;
  // Variable declarations only count as scope-config assignments when the
  // initializer is a literal value shape. Generic CallExpression initializers
  // (e.g. `requestedScope.split(' ')` inside a validator function) are
  // intermediate state, not configuration.
  if (
    !ts.isStringLiteral(node.initializer) &&
    !ts.isNoSubstitutionTemplateLiteral(node.initializer) &&
    !ts.isTemplateExpression(node.initializer) &&
    !ts.isArrayLiteralExpression(node.initializer)
  ) {
    return;
  }
  const assignment = buildAssignment(
    node.name.text,
    false,
    node,
    node.initializer,
    sf,
    file,
  );
  if (assignment) out.push(assignment);
}

// ─── Value classification ──────────────────────────────────────────────────

function buildAssignment(
  propertyName: string,
  matchedViaOAuthContext: boolean,
  carrier: ts.Node,
  value: ts.Expression,
  sf: ts.SourceFile,
  file: string,
): ScopeAssignment | null {
  const valueShape = classifyValueShape(value);
  const scopesCollected = collectScopeStrings(value);
  const broadScopes = classifyScopeList(scopesCollected);
  const userInputChain: string[] = [];
  const userControlled = isUserInputValue(value, userInputChain);

  // A finding is produced when EITHER we observed at least one broad scope
  // OR the scope value is user-controlled (any user-controlled scope is a
  // finding regardless of the specific token — the value is unknown).
  if (broadScopes.length === 0 && !userControlled) return null;

  const worstSeverity = worstSeverityOf(broadScopes);
  const location = sourceLocation(sf, file, carrier);
  const valueLocation = sourceLocation(sf, file, value);
  const valueText = value.getText(sf).trim().slice(0, 200);
  const lineText = lineTextAt(sf, carrier.getStart(sf)).trim().slice(0, 200);

  return {
    propertyName,
    matchedViaOAuthContext,
    valueText,
    lineText,
    location,
    valueLocation,
    broadScopes,
    worstSeverity,
    userControlled,
    userInputChain,
    valueShape,
  };
}

function classifyValueShape(value: ts.Expression): ScopeAssignment["valueShape"] {
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) return "string";
  if (ts.isArrayLiteralExpression(value)) return "array";
  if (ts.isTemplateExpression(value)) return "template";
  if (ts.isIdentifier(value)) return "identifier";
  if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
    return "property-access";
  }
  return "other";
}

/** Collect scope-string values from the expression, flattening arrays and whitespace-delimited strings. */
function collectScopeStrings(value: ts.Expression): string[] {
  const out: string[] = [];
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
    const raw = value.text;
    for (const s of splitWhitespace(raw)) {
      if (s) out.push(s);
    }
    return out;
  }
  if (ts.isArrayLiteralExpression(value)) {
    for (const el of value.elements) {
      if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) {
        for (const s of splitWhitespace(el.text)) {
          if (s) out.push(s);
        }
      }
    }
    return out;
  }
  return out;
}

function splitWhitespace(s: string): string[] {
  const tokens: string[] = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === ",") {
      if (buf) {
        tokens.push(buf);
        buf = "";
      }
      continue;
    }
    buf += ch;
  }
  if (buf) tokens.push(buf);
  return tokens;
}

function classifyScopeList(scopes: string[]): ScopeMatch[] {
  const out: ScopeMatch[] = [];
  for (const raw of scopes) {
    const m = classifyScope(raw);
    if (m) out.push(m);
  }
  return out;
}

export function classifyScope(raw: string): ScopeMatch | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  // 1. Exact wildcard token.
  if (WILDCARD_TOKEN_SET.has(trimmed)) {
    return { scope: trimmed, severity: "wildcard", rationale: "exact wildcard token" };
  }

  const lower = trimmed.toLowerCase();

  // 2. Exact admin token (lowercased exact match).
  if (ADMIN_TOKEN_SET.has(lower)) {
    return { scope: trimmed, severity: "admin", rationale: "exact admin token" };
  }

  // 3. Broad-prefixed exact token (read:all, write:all, ...).
  if (BROAD_PREFIXED_TOKEN_SET.has(lower)) {
    return { scope: trimmed, severity: "broad", rationale: "exact broad-prefixed token" };
  }

  // 4. Structural segment check on ":" and "." — a scope ID is flagged when
  // EITHER the first segment (authority level, e.g. "admin:org") OR the last
  // segment (admin namespace suffix, e.g. "bigquery.admin") carries a
  // wildcard/admin marker. Requiring the delimiter to be present avoids
  // false-positives on compound identifiers without structure ("admin_panel").
  for (const sep of [":", "."]) {
    if (!lower.includes(sep)) continue;
    const segments = splitOn(lower, sep);
    const first = segments[0];
    const last = segments[segments.length - 1];

    if (WILDCARD_SUFFIX_SET.has(first) || WILDCARD_SUFFIX_SET.has(last)) {
      return { scope: trimmed, severity: "wildcard", rationale: `${sep}-delimited wildcard segment` };
    }
    if (ADMIN_SUFFIX_SET.has(first)) {
      return { scope: trimmed, severity: "admin", rationale: `${sep}-delimited admin prefix` };
    }
    if (ADMIN_SUFFIX_SET.has(last)) {
      return { scope: trimmed, severity: "admin", rationale: `${sep}-delimited admin suffix` };
    }
  }
  return null;
}

function splitOn(s: string, sep: string): string[] {
  const out: string[] = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === sep) {
      out.push(buf);
      buf = "";
    } else {
      buf += s[i];
    }
  }
  out.push(buf);
  return out;
}

function worstSeverityOf(matches: ScopeMatch[]): ScopeSeverity | null {
  if (matches.length === 0) return null;
  if (matches.some((m) => m.severity === "wildcard")) return "wildcard";
  if (matches.some((m) => m.severity === "admin")) return "admin";
  return "broad";
}

// ─── OAuth-context resolution ──────────────────────────────────────────────

function enclosingObjectHasOAuthContext(prop: ts.PropertyAssignment): boolean {
  const parent = prop.parent;
  if (!parent || !ts.isObjectLiteralExpression(parent)) return false;
  for (const p of parent.properties) {
    if (!ts.isPropertyAssignment(p)) continue;
    const name = propertyNameText(p.name);
    if (!name) continue;
    if (OAUTH_CONTEXT_KEY_SET.has(name.toLowerCase())) return true;
  }
  return false;
}

// ─── User-input resolution ─────────────────────────────────────────────────

function isUserInputValue(value: ts.Expression, chain: string[]): boolean {
  // Template literal: scan spans.
  if (ts.isTemplateExpression(value)) {
    for (const span of value.templateSpans) {
      if (isUserInputValue(span.expression, chain)) return true;
    }
    return false;
  }
  if (ts.isParenthesizedExpression(value)) return isUserInputValue(value.expression, chain);
  if (ts.isAwaitExpression(value)) return isUserInputValue(value.expression, chain);
  if (ts.isAsExpression(value)) return isUserInputValue(value.expression, chain);
  if (ts.isCallExpression(value)) {
    // If the callee is a PropertyAccess chain starting at a user-input receiver,
    // the call's RESULT can be assumed user-controlled too (JSON.parse, Object.assign).
    if (ts.isPropertyAccessExpression(value.expression)) {
      return isUserInputValue(value.expression.expression, chain);
    }
    return false;
  }
  if (ts.isIdentifier(value)) {
    const name = value.text;
    if (USER_INPUT_IDENTIFIER_SET.has(name) || USER_INPUT_IDENTIFIER_SET.has(name.toLowerCase())) {
      chain.push(name);
      return true;
    }
    if (USER_INPUT_RECEIVER_SET.has(name.toLowerCase())) {
      chain.push(name);
      return true;
    }
    return false;
  }
  if (ts.isPropertyAccessExpression(value)) {
    const chainParts: string[] = [];
    let cursor: ts.Expression = value;
    while (ts.isPropertyAccessExpression(cursor)) {
      chainParts.unshift(cursor.name.text);
      cursor = cursor.expression;
    }
    if (ts.isIdentifier(cursor)) {
      chainParts.unshift(cursor.text);
      const root = cursor.text.toLowerCase();
      if (USER_INPUT_RECEIVER_SET.has(root)) {
        // Well-known root (`req`, `body`) → user-controlled.
        chain.push(...chainParts);
        return true;
      }
      // Generic root (`ctx`, `context`, `event`) requires a marker in the chain.
      if (
        (root === "ctx" || root === "context" || root === "event" || root === "args") &&
        chainParts.some((p) => USER_INPUT_CHAIN_SET.has(p.toLowerCase()))
      ) {
        chain.push(...chainParts);
        return true;
      }
    }
    return false;
  }
  if (ts.isElementAccessExpression(value)) {
    // `req["scope"]` — treat base as the user-input source.
    return isUserInputValue(value.expression, chain);
  }
  return false;
}

// ─── AST helpers ───────────────────────────────────────────────────────────

function propertyNameText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteral(name) || ts.isNoSubstitutionTemplateLiteral(name)) return name.text;
  return null;
}

function tailIdentifierOfExpression(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) return expr.name.text;
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
