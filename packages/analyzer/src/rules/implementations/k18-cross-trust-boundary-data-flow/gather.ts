/**
 * K18 gather — cross-trust-boundary data flow.
 *
 * Within each function body, tracks sensitive values introduced by env
 * access, credential-shaped calls, sensitive-path file reads, or
 * sensitivity-named parameters; then inspects every ReturnStatement and
 * response-emitting / network-send call for whether a tainted value
 * reaches it without a same-variable redactor.
 *
 * Zero regex. Vocabulary in `./data/sensitivity-vocabulary.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  SENSITIVITY_TOKENS,
  ENV_SENSITIVE_SUFFIXES,
  CREDENTIAL_RECEIVER_TOKENS,
  CREDENTIAL_METHOD_TOKENS,
  SENSITIVE_PATH_PREFIXES,
  REDACTOR_CALL_IDENTIFIERS,
  REDACTOR_RECEIVER_METHODS,
  RESPONSE_RECEIVERS,
  RESPONSE_METHODS,
  NETWORK_SEND_METHODS,
  TEST_RUNNER_MODULES,
  TEST_RUNNER_TOPLEVEL,
} from "./data/sensitivity-vocabulary.js";

// ─── Vocabulary sets ───────────────────────────────────────────────────────

const SENSITIVITY_SET: ReadonlySet<string> = new Set(
  Object.keys(SENSITIVITY_TOKENS).map((k) => k.toLowerCase()),
);
const ENV_SUFFIX_SET: ReadonlySet<string> = new Set(
  Object.keys(ENV_SENSITIVE_SUFFIXES).map((k) => k.toLowerCase()),
);
const CREDENTIAL_RECEIVER_SET: ReadonlySet<string> = new Set(
  Object.keys(CREDENTIAL_RECEIVER_TOKENS).map((k) => k.toLowerCase()),
);
const CREDENTIAL_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(CREDENTIAL_METHOD_TOKENS).map((k) => k.toLowerCase()),
);
const SENSITIVE_PATH_SET: ReadonlySet<string> = new Set(
  Object.keys(SENSITIVE_PATH_PREFIXES),
);
const REDACTOR_CALL_SET: ReadonlySet<string> = new Set(
  Object.keys(REDACTOR_CALL_IDENTIFIERS).map((k) => k.toLowerCase()),
);
const RESPONSE_RECEIVER_SET: ReadonlySet<string> = new Set(
  Object.keys(RESPONSE_RECEIVERS).map((k) => k.toLowerCase()),
);
const RESPONSE_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(RESPONSE_METHODS).map((k) => k.toLowerCase()),
);
const NETWORK_SEND_METHOD_SET: ReadonlySet<string> = new Set(
  Object.keys(NETWORK_SEND_METHODS).map((k) => k.toLowerCase()),
);
const TEST_MODULE_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_MODULES));
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_TOPLEVEL));

// ─── Public types ──────────────────────────────────────────────────────────

export type SensitiveSourceKind =
  | "env-secret"
  | "credential-call"
  | "sensitive-path"
  | "sensitive-param";

export type SinkKind = "return-statement" | "response-call" | "network-send";

export interface SensitiveSource {
  kind: SensitiveSourceKind;
  location: Location;
  identifier: string | null;
  observed: string;
}

export interface CrossBoundaryFlow {
  source: SensitiveSource;
  sinkKind: SinkKind;
  sinkLocation: Location;
  enclosingFunctionLocation: Location | null;
  redactor: {
    present: boolean;
    sameVariable: boolean;
    detail: string;
  };
  // True when the sensitivity classification rests only on a parameter name
  // heuristic (no corresponding call / env access). Down-weighted.
  paramNameOnly: boolean;
}

export interface FileEvidence {
  file: string;
  isTestFile: boolean;
  flows: CrossBoundaryFlow[];
}

export interface K18Gathered {
  perFile: FileEvidence[];
}

// ─── Entry ─────────────────────────────────────────────────────────────────

export function gatherK18(context: AnalysisContext): K18Gathered {
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
  const flows: CrossBoundaryFlow[] = [];
  if (!isTestFile) {
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
  flows: CrossBoundaryFlow[],
): void {
  const fnLoc = sourceLocation(sf, file, fn);
  const body: ts.ConciseBody | undefined = fn.body;
  if (!body) return;
  // Narrowed alias for TypeScript's type-flow analysis through closures.
  const bodyNode: ts.Node = body;

  // Map of identifier → SensitiveSource. `paramNameOnly` tracked per name.
  const tainted = new Map<string, SensitiveSource>();
  const paramNameOnlyTainted = new Set<string>();

  // Parameters whose names look sensitive (softer signal).
  for (const p of fn.parameters) {
    if (!ts.isIdentifier(p.name)) continue;
    if (identifierContainsSensitivityToken(p.name.text)) {
      tainted.set(p.name.text, {
        kind: "sensitive-param",
        location: sourceLocation(sf, file, p),
        identifier: p.name.text,
        observed: `parameter \`${p.name.text}\``.slice(0, 200),
      });
      paramNameOnlyTainted.add(p.name.text);
    }
  }

  // Pass 1 — scan for sensitive source bindings with a fixed-point walk to
  // propagate taint through variable assignments AND object literal
  // composition that carries a tainted identifier.
  let changed = true;
  while (changed) {
    changed = false;
    function scanVars(n: ts.Node): void {
      if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer) {
        const name = n.name.text;
        if (tainted.has(name) && !paramNameOnlyTainted.has(name)) {
          ts.forEachChild(n, scanVars);
          return;
        }
        // Redactor-cleansed.
        if (initializerIsRedactor(n.initializer)) {
          tainted.delete(name);
          ts.forEachChild(n, scanVars);
          return;
        }
        const direct = classifyExpressionAsSensitive(n.initializer, sf, file);
        if (direct !== null) {
          tainted.set(name, { ...direct, identifier: name });
          paramNameOnlyTainted.delete(name);
          changed = true;
        } else {
          // Propagate taint via reference.
          const origin = findTaintedInitializerSource(n.initializer, tainted);
          if (origin !== null) {
            tainted.set(name, {
              ...origin,
              location: sourceLocation(sf, file, n),
              identifier: name,
              observed: lineTextAt(sf, n.getStart(sf)).trim().slice(0, 200),
            });
            // Preserve paramNameOnly if the origin was paramName-only.
            if (origin.identifier && paramNameOnlyTainted.has(origin.identifier)) {
              paramNameOnlyTainted.add(name);
            }
            changed = true;
          }
        }
      }
      ts.forEachChild(n, scanVars);
    }
    scanVars(bodyNode);
  }

  // Pass 2 — inspect ReturnStatements and response-call / network-send sinks.
  function scanSinks(n: ts.Node): void {
    if (ts.isReturnStatement(n) && n.expression) {
      evaluateSink(n.expression, "return-statement", n);
    }
    if (ts.isCallExpression(n)) {
      if (isResponseCall(n)) {
        for (const arg of n.arguments) evaluateSink(arg, "response-call", n);
      } else if (isNetworkSendCall(n)) {
        for (const arg of n.arguments) evaluateSink(arg, "network-send", n);
      }
    }
    ts.forEachChild(n, scanSinks);
  }
  scanSinks(bodyNode);

  function evaluateSink(expr: ts.Expression, sinkKind: SinkKind, anchor: ts.Node): void {
    // Look for either an inline sensitive source or a tainted identifier.
    const inline = findSensitiveInExpression(expr, sf, file);
    let source: SensitiveSource | null = inline;
    let returnedIdentifier: string | null = null;
    const taintedRef = findTaintedDescendantIdentifier(expr, tainted);
    if (taintedRef) {
      returnedIdentifier = taintedRef;
      if (!source) source = tainted.get(taintedRef) ?? null;
    }
    if (!source) return;

    const redactor = redactorAppliedTo(
      bodyNode,
      returnedIdentifier ?? source.identifier ?? null,
    );

    flows.push({
      source,
      sinkKind,
      sinkLocation: sourceLocation(sf, file, anchor),
      enclosingFunctionLocation: fnLoc,
      redactor,
      paramNameOnly:
        source.kind === "sensitive-param" &&
        (returnedIdentifier !== null
          ? paramNameOnlyTainted.has(returnedIdentifier)
          : source.identifier !== null && paramNameOnlyTainted.has(source.identifier)),
    });
  }
}

// ─── Sensitivity classification ────────────────────────────────────────────

function classifyExpressionAsSensitive(
  expr: ts.Expression,
  sf: ts.SourceFile,
  file: string,
): SensitiveSource | null {
  const bare = unwrapAwait(expr);

  // process.env.XYZ
  if (ts.isPropertyAccessExpression(bare) && isProcessEnvAccess(bare)) {
    const envName = bare.name.text.toLowerCase();
    if (envNameIsSensitive(envName)) {
      return {
        kind: "env-secret",
        location: sourceLocation(sf, file, bare),
        identifier: null,
        observed: `process.env.${bare.name.text}`.slice(0, 200),
      };
    }
  }

  // Credential-shaped call: receiver.method OR bare call containing credential token
  if (ts.isCallExpression(bare)) {
    if (ts.isPropertyAccessExpression(bare.expression)) {
      const r = ts.isIdentifier(bare.expression.expression)
        ? bare.expression.expression.text.toLowerCase()
        : null;
      const m = bare.expression.name.text.toLowerCase();
      if ((r && CREDENTIAL_RECEIVER_SET.has(r)) || CREDENTIAL_METHOD_SET.has(m)) {
        return {
          kind: "credential-call",
          location: sourceLocation(sf, file, bare),
          identifier: null,
          observed: `${r ?? "?"}.${bare.expression.name.text}(...)`.slice(0, 200),
        };
      }
    }
    if (ts.isIdentifier(bare.expression)) {
      const id = bare.expression.text.toLowerCase();
      if (CREDENTIAL_METHOD_SET.has(id)) {
        return {
          kind: "credential-call",
          location: sourceLocation(sf, file, bare),
          identifier: null,
          observed: `${bare.expression.text}(...)`.slice(0, 200),
        };
      }
    }
  }

  // readFileSync on a sensitive path literal
  if (ts.isCallExpression(bare)) {
    if (isFileReadCall(bare)) {
      const arg = bare.arguments[0];
      if (arg && (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))) {
        const lower = arg.text.toLowerCase();
        for (const prefix of SENSITIVE_PATH_SET) {
          if (lower.includes(prefix)) {
            return {
              kind: "sensitive-path",
              location: sourceLocation(sf, file, bare),
              identifier: null,
              observed: `read of "${arg.text}"`.slice(0, 200),
            };
          }
        }
      }
    }
  }

  return null;
}

function isProcessEnvAccess(pa: ts.PropertyAccessExpression): boolean {
  if (!ts.isPropertyAccessExpression(pa.expression)) return false;
  if (!ts.isIdentifier(pa.expression.expression)) return false;
  return pa.expression.expression.text === "process" && pa.expression.name.text === "env";
}

function envNameIsSensitive(name: string): boolean {
  const lower = name.toLowerCase();
  for (const suffix of ENV_SUFFIX_SET) {
    if (lower === suffix || lower.includes(suffix)) return true;
  }
  return false;
}

function isFileReadCall(call: ts.CallExpression): boolean {
  if (ts.isIdentifier(call.expression)) {
    const id = call.expression.text.toLowerCase();
    return id === "readfile" || id === "readfilesync";
  }
  if (ts.isPropertyAccessExpression(call.expression)) {
    const m = call.expression.name.text.toLowerCase();
    return m === "readfile" || m === "readfilesync" || m === "readtext";
  }
  return false;
}

function identifierContainsSensitivityToken(name: string): boolean {
  const lower = name.toLowerCase();
  for (const token of SENSITIVITY_SET) {
    if (lower === token || lower.includes(token)) return true;
  }
  return false;
}

function unwrapAwait(expr: ts.Expression): ts.Expression {
  let cur: ts.Expression = expr;
  while (ts.isAwaitExpression(cur) || ts.isParenthesizedExpression(cur)) {
    cur = cur.expression;
  }
  return cur;
}

/**
 * Walk an expression tree looking for any descendant classified as
 * sensitive (used when the sink contains the source inline rather than
 * referencing a bound variable).
 */
function findSensitiveInExpression(
  expr: ts.Expression,
  sf: ts.SourceFile,
  file: string,
): SensitiveSource | null {
  let found: SensitiveSource | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    const s = classifyExpressionAsSensitive(n as ts.Expression, sf, file);
    if (s !== null) {
      found = s;
      return;
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

function findTaintedInitializerSource(
  expr: ts.Expression,
  tainted: Map<string, SensitiveSource>,
): SensitiveSource | null {
  let found: SensitiveSource | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n)) {
      const src = tainted.get(n.text);
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
  tainted: Map<string, SensitiveSource>,
): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n) && tainted.has(n.text)) {
      found = n.text;
      return;
    }
    ts.forEachChild(n, visit);
  }
  visit(expr);
  return found;
}

// ─── Sink classification ──────────────────────────────────────────────────

function isResponseCall(call: ts.CallExpression): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const method = call.expression.name.text.toLowerCase();
  if (!RESPONSE_METHOD_SET.has(method)) return false;
  const receiver = call.expression.expression;
  if (!ts.isIdentifier(receiver)) return false;
  return RESPONSE_RECEIVER_SET.has(receiver.text.toLowerCase());
}

function isNetworkSendCall(call: ts.CallExpression): boolean {
  // fetch(url, { body })
  if (ts.isIdentifier(call.expression) && call.expression.text.toLowerCase() === "fetch") return true;
  // axios.post(url, body) / http.post(...) / webhook.send(...)
  if (ts.isPropertyAccessExpression(call.expression)) {
    const m = call.expression.name.text.toLowerCase();
    if (NETWORK_SEND_METHOD_SET.has(m)) return true;
  }
  return false;
}

// ─── Redactor check ────────────────────────────────────────────────────────

function redactorAppliedTo(
  body: ts.Node,
  identifier: string | null,
): { present: boolean; sameVariable: boolean; detail: string } {
  let anyRedactor = false;
  let sameVariable = false;
  let detail = "no redactor observed in the enclosing function body";

  function visit(n: ts.Node): void {
    if (!ts.isCallExpression(n)) {
      ts.forEachChild(n, visit);
      return;
    }
    if (ts.isIdentifier(n.expression) && REDACTOR_CALL_SET.has(n.expression.text.toLowerCase())) {
      anyRedactor = true;
      if (identifier !== null && callArgumentsReferenceIdentifier(n, identifier)) {
        sameVariable = true;
        detail = `redactor \`${n.expression.text}(...)\` applied to \`${identifier}\``;
        return;
      } else if (!sameVariable) {
        detail =
          identifier !== null
            ? `redactor \`${n.expression.text}(...)\` present but NOT applied to \`${identifier}\``
            : `redactor \`${n.expression.text}(...)\` present in scope`;
      }
    }
    if (ts.isPropertyAccessExpression(n.expression) && ts.isIdentifier(n.expression.expression)) {
      const r = n.expression.expression.text.toLowerCase();
      const m = n.expression.name.text.toLowerCase();
      const methods = REDACTOR_RECEIVER_METHODS[r];
      if (methods && methods[m]) {
        anyRedactor = true;
        if (identifier !== null && callArgumentsReferenceIdentifier(n, identifier)) {
          sameVariable = true;
          detail = `redactor \`${r}.${m}(...)\` applied to \`${identifier}\``;
          return;
        } else if (!sameVariable) {
          detail =
            identifier !== null
              ? `redactor \`${r}.${m}(...)\` present but NOT applied to \`${identifier}\``
              : `redactor \`${r}.${m}(...)\` present in scope`;
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  visit(body);
  return { present: anyRedactor, sameVariable, detail };
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

function initializerIsRedactor(expr: ts.Expression): boolean {
  const bare = unwrapAwait(expr);
  if (!ts.isCallExpression(bare)) return false;
  if (ts.isIdentifier(bare.expression)) {
    return REDACTOR_CALL_SET.has(bare.expression.text.toLowerCase());
  }
  if (ts.isPropertyAccessExpression(bare.expression) && ts.isIdentifier(bare.expression.expression)) {
    const r = bare.expression.expression.text.toLowerCase();
    const m = bare.expression.name.text.toLowerCase();
    const methods = REDACTOR_RECEIVER_METHODS[r];
    return Boolean(methods && methods[m]);
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
