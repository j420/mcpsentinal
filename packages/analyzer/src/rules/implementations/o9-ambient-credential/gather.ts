/**
 * O9 gather step — AST detection of filesystem reads that target
 * ambient user-scoped credential paths.
 *
 * Zero regex. Classifies calls of the form:
 *
 *   fs.readFileSync("~/.aws/credentials")
 *   fs.readFile(path.join(homedir(), ".ssh", "id_rsa"), ...)
 *   open(process.env.GOOGLE_APPLICATION_CREDENTIALS)
 *
 * against the shared vocabulary in data/vocabulary.ts. The receiver
 * or bare identifier must be one of FS_READ_PRIMITIVES; the first
 * argument must resolve to an ambient path either via literal
 * substring, path.join fragments, or env-var indirection.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  FS_READ_PRIMITIVES,
  AMBIENT_PATH_FRAGMENTS,
  AMBIENT_PATH_ENV_VARS,
  PATH_JOIN_FRAGMENTS,
  HOMEDIR_CALLS,
} from "./data/vocabulary.js";

const FS_PRIM_SET: ReadonlySet<string> = new Set(Object.keys(FS_READ_PRIMITIVES));
const AMBIENT_LITERAL_FRAGMENTS: readonly string[] = Object.keys(AMBIENT_PATH_FRAGMENTS);
const ENV_VAR_SET: ReadonlySet<string> = new Set(Object.keys(AMBIENT_PATH_ENV_VARS));
const PATH_JOIN_SET: ReadonlySet<string> = new Set(Object.keys(PATH_JOIN_FRAGMENTS));
const HOMEDIR_SET: ReadonlySet<string> = new Set(Object.keys(HOMEDIR_CALLS));

export type AmbientCredentialHitKind =
  | "literal-path"          // fs.readFileSync("~/.ssh/id_rsa")
  | "template-path"         // `${home}/.aws/credentials`
  | "path-join"             // path.join(homedir(), ".ssh", "id_rsa")
  | "env-var-indirection";  // fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS)

export interface AmbientCredentialSite {
  kind: AmbientCredentialHitKind;
  /** Fragment / env-var that triggered the classification. */
  marker: string;
  /** Short human label drawn from the vocabulary. */
  label: string;
  /** Source-kind Location of the fs-read call. */
  location: Location;
  /** Enclosing function location (null for top-level). */
  enclosingFunctionLocation: Location | null;
  /** Snippet for narrative. */
  observed: string;
}

export interface O9Gathered {
  sites: AmbientCredentialSite[];
  isTestFile: boolean;
}

export function gatherO9(context: AnalysisContext): O9Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], isTestFile: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );
  if (detectTestFileStructurally(sf)) return { sites: [], isTestFile: true };

  const sites: AmbientCredentialSite[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node) && isFsReadPrimitive(node)) {
      const arg = node.arguments[0];
      if (arg) {
        const hit = classifyArg(arg);
        if (hit) {
          const enclosing = findEnclosingFunction(node);
          sites.push({
            ...hit,
            location: sourceLocation(sf, node),
            enclosingFunctionLocation: enclosing ? sourceLocation(sf, enclosing) : null,
            observed: lineTextAt(sf, node.getStart(sf)).trim().slice(0, 200),
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  });

  return { sites, isTestFile: false };
}

function isFsReadPrimitive(call: ts.CallExpression): boolean {
  if (ts.isPropertyAccessExpression(call.expression)) {
    const method = call.expression.name.text.toLowerCase();
    return FS_PRIM_SET.has(method);
  }
  if (ts.isIdentifier(call.expression)) {
    const name = call.expression.text.toLowerCase();
    return FS_PRIM_SET.has(name);
  }
  return false;
}

function classifyArg(
  arg: ts.Expression,
): { kind: AmbientCredentialHitKind; marker: string; label: string } | null {
  // Unwrap TS type assertions and parentheses — `x as string`,
  // `(x)`, `<T>x` — before classifying.
  let inner = arg;
  while (
    ts.isAsExpression(inner) ||
    ts.isParenthesizedExpression(inner) ||
    ts.isTypeAssertionExpression(inner) ||
    ts.isNonNullExpression(inner)
  ) {
    inner = inner.expression;
  }
  arg = inner;
  // Case 1: string / template literal with an ambient fragment as a
  // substring.
  const literal = staticStringValue(arg);
  if (literal !== null) {
    for (const frag of AMBIENT_LITERAL_FRAGMENTS) {
      if (literal.includes(frag)) {
        return {
          kind: ts.isTemplateExpression(arg) ? "template-path" : "literal-path",
          marker: frag,
          label: AMBIENT_PATH_FRAGMENTS[frag],
        };
      }
    }
  }
  // Case 2: path.join(...) containing a PATH_JOIN fragment and a
  // homedir call.
  if (ts.isCallExpression(arg)) {
    const joined = tryPathJoin(arg);
    if (joined) return joined;
  }
  // Case 3: env-var indirection — process.env.GOOGLE_APPLICATION_CREDENTIALS
  // or os.environ["KEY"].
  const envVar = tryEnvVarIndirection(arg);
  if (envVar) return envVar;
  return null;
}

function staticStringValue(expr: ts.Expression): string | null {
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    return expr.text;
  }
  if (ts.isTemplateExpression(expr)) {
    // Walk the template: concatenate all raw text parts so an
    // embedded substring token ( ".aws/credentials" ) is still
    // visible even when interleaved with expressions.
    let buf = expr.head.text;
    for (const span of expr.templateSpans) buf += span.literal.text;
    return buf;
  }
  return null;
}

function tryPathJoin(
  call: ts.CallExpression,
): { kind: AmbientCredentialHitKind; marker: string; label: string } | null {
  // Detect path.join / os.path.join / bare `join()` where at least
  // one argument matches a PATH_JOIN fragment AND at least one
  // argument is a call to a homedir helper.
  if (ts.isPropertyAccessExpression(call.expression)) {
    const method = call.expression.name.text.toLowerCase();
    if (method !== "join") return null;
  } else if (ts.isIdentifier(call.expression)) {
    if (call.expression.text.toLowerCase() !== "join") return null;
  } else {
    return null;
  }
  let fragmentHit: string | null = null;
  let homedirObserved = false;
  for (const arg of call.arguments) {
    if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) {
      if (PATH_JOIN_SET.has(arg.text)) fragmentHit = arg.text;
    } else if (ts.isCallExpression(arg) && isHomedirCall(arg)) {
      homedirObserved = true;
    } else if (
      ts.isPropertyAccessExpression(arg) &&
      ts.isIdentifier(arg.expression) &&
      arg.expression.text === "process" &&
      arg.name.text === "env"
    ) {
      // process.env referenced in join — treated as homedir
      // equivalent (user-scoped).
      homedirObserved = true;
    }
  }
  if (fragmentHit && homedirObserved) {
    return {
      kind: "path-join",
      marker: fragmentHit,
      label: PATH_JOIN_FRAGMENTS[fragmentHit] ?? `path fragment ${fragmentHit}`,
    };
  }
  return null;
}

function isHomedirCall(call: ts.CallExpression): boolean {
  if (ts.isIdentifier(call.expression)) {
    return HOMEDIR_SET.has(call.expression.text);
  }
  if (ts.isPropertyAccessExpression(call.expression)) {
    return HOMEDIR_SET.has(call.expression.name.text);
  }
  return false;
}

function tryEnvVarIndirection(
  arg: ts.Expression,
): { kind: AmbientCredentialHitKind; marker: string; label: string } | null {
  // process.env.GOOGLE_APPLICATION_CREDENTIALS
  if (ts.isPropertyAccessExpression(arg)) {
    const outerName = arg.name.text;
    const head = arg.expression;
    if (
      ts.isPropertyAccessExpression(head) &&
      ts.isIdentifier(head.expression) &&
      head.expression.text === "process" &&
      head.name.text === "env" &&
      ENV_VAR_SET.has(outerName)
    ) {
      return {
        kind: "env-var-indirection",
        marker: outerName,
        label: AMBIENT_PATH_ENV_VARS[outerName] ?? outerName,
      };
    }
  }
  // os.environ["KEY"] / process.env["KEY"]
  if (ts.isElementAccessExpression(arg)) {
    const head = arg.expression;
    if (
      ts.isPropertyAccessExpression(head) &&
      ts.isIdentifier(head.expression) &&
      head.expression.text === "process" &&
      head.name.text === "env"
    ) {
      const keyNode = arg.argumentExpression;
      if (ts.isStringLiteral(keyNode) && ENV_VAR_SET.has(keyNode.text)) {
        return {
          kind: "env-var-indirection",
          marker: keyNode.text,
          label: AMBIENT_PATH_ENV_VARS[keyNode.text] ?? keyNode.text,
        };
      }
    }
  }
  return null;
}

// ─── shared helpers ───────────────────────────────────────────────────────

function findEnclosingFunction(node: ts.Node): ts.Node | null {
  let cur: ts.Node | undefined = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur)
    ) {
      return cur;
    }
    cur = cur.parent;
  }
  return null;
}

const TEST_RUNNER_MODULES: ReadonlySet<string> = new Set([
  "vitest",
  "mocha",
  "jest",
  "node:test",
  "tap",
]);

const TEST_TOPLEVEL: ReadonlySet<string> = new Set([
  "describe",
  "it",
  "test",
  "suite",
  "specify",
]);

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelItOrTest = 0;
  let topLevelRunnerCalls = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_RUNNER_MODULES.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee) && TEST_TOPLEVEL.has(callee.text)) {
        topLevelRunnerCalls++;
        if (callee.text === "it" || callee.text === "test") topLevelItOrTest++;
      }
    }
  }
  if (topLevelItOrTest > 0) return true;
  return topLevelRunnerCalls > 0 && (hasRunnerImport || topLevelRunnerCalls >= 2);
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

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  return sf.text.split("\n")[line] ?? "";
}
