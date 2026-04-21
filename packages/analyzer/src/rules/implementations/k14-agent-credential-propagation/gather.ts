/**
 * K14 gather — Agent Credential Propagation via Shared State.
 *
 * Detects credential-bearing identifiers flowing into a cross-agent
 * shared-state writer call. Strategies:
 *
 *   - encoder-passthrough-taint   — taint follows base64 / Buffer / JWT.sign
 *   - alias-binding-resolution    — `const s = sharedStore` resolved
 *   - cross-function-helper-walk  — one hop into a helper that writes
 *   - placeholder-literal-suppression — REPLACE_ME / <token> ⇒ no fire
 *
 * Zero regex. All vocabulary lives in `data/credential-vocab.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CREDENTIAL_IDENTIFIERS,
  SHARED_STATE_RECEIVERS,
  SHARED_STATE_WRITERS,
  ENCODER_PASSTHROUGHS,
  REDACTOR_CALLS,
  REDACTOR_RECEIVER_METHODS,
  PLACEHOLDER_LITERALS,
  TEST_RUNNER_MODULES,
  TEST_TOPLEVEL_IDENTIFIERS,
} from "./data/credential-vocab.js";

const CREDENTIAL_SET: ReadonlySet<string> = new Set(Object.keys(CREDENTIAL_IDENTIFIERS));
const SHARED_RECEIVER_SET: ReadonlySet<string> = new Set(Object.keys(SHARED_STATE_RECEIVERS));
const SHARED_WRITER_SET: ReadonlySet<string> = new Set(Object.keys(SHARED_STATE_WRITERS));
const ENCODER_SET: ReadonlySet<string> = new Set(Object.keys(ENCODER_PASSTHROUGHS));
const REDACTOR_CALL_SET: ReadonlySet<string> = new Set(Object.keys(REDACTOR_CALLS));
const PLACEHOLDER_SET: ReadonlySet<string> = new Set(Object.keys(PLACEHOLDER_LITERALS));
const TEST_RUNNER_SET: ReadonlySet<string> = new Set(Object.keys(TEST_RUNNER_MODULES));
const TEST_TOPLEVEL_SET: ReadonlySet<string> = new Set(Object.keys(TEST_TOPLEVEL_IDENTIFIERS));

export type K14EvidenceKind =
  | "direct-credential-write"
  | "alias-credential-write"
  | "encoder-wrapped-credential-write"
  | "cross-function-helper-write";

export interface CredentialPropagationSite {
  /** Sink call location (the shared-state writer call). */
  location: Location;
  /** Source location of the credential binding (variable / parameter). */
  credentialSourceLocation: Location;
  /** Enclosing function location for the mitigation check, if any. */
  enclosingFunctionLocation: Location | null;
  /** Which sub-strategy fired. */
  kind: K14EvidenceKind;
  /** The credential identifier name (lowercased). */
  credentialName: string;
  /** The shared-state receiver name observed (post-alias resolution). */
  receiverName: string;
  /** The writer method name (lowercased). */
  writerMethod: string;
  /** Whether a redactor call was observed in the enclosing scope. */
  enclosingHasRedactor: boolean;
  /** Whether RHS is a placeholder literal — set means the call should be suppressed. */
  rhsIsPlaceholder: boolean;
  /** Single-line text snippet of the sink for narrative use. */
  observed: string;
}

export interface FileEvidence {
  file: string;
  sites: CredentialPropagationSite[];
  isTestFile: boolean;
}

export interface K14Gathered {
  perFile: FileEvidence[];
}

export function gatherK14(context: AnalysisContext): K14Gathered {
  const perFile: FileEvidence[] = [];
  for (const [file, text] of collectSourceFiles(context)) {
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
  if (isTestFile) {
    return { file, sites: [], isTestFile: true };
  }

  // Build per-file metadata in a single AST pass:
  //   - aliasMap: const s = sharedStore   ⇒  s -> sharedStore
  //   - credentialBindings: variable / parameter names that hold credentials
  //   - helperFunctions: name → function declaration that writes to shared state
  const aliasMap = new Map<string, string>();
  const credentialBindings = new Set<string>();
  const helpers = collectHelpers(sf);
  collectAliasesAndCredentials(sf, aliasMap, credentialBindings);

  const sites: CredentialPropagationSite[] = [];
  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const direct = classifySharedStateWriterCall(node, sf, aliasMap);
      if (direct) {
        const cred = classifyCredentialArguments(node, sf, credentialBindings);
        if (cred) {
          sites.push(buildSite(node, sf, file, direct, cred));
        }
      } else {
        // cross-function-helper-walk: this call invokes a helper that writes
        // shared state, and one of the arguments is a credential binding.
        const helperCall = classifyHelperCall(node, sf, helpers);
        if (helperCall) {
          const cred = classifyCredentialArguments(node, sf, credentialBindings);
          if (cred) {
            sites.push(buildSite(node, sf, file, helperCall, cred));
          }
        }
      }
    }
    // Direct property assignment:  sharedState.token = tok;
    if (ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isPropertyAccessExpression(node.left)) {
      const site = classifyPropertyAssignment(node, sf, file, aliasMap, credentialBindings);
      if (site) sites.push(site);
    }
    ts.forEachChild(node, visit);
  });

  return { file, sites, isTestFile: false };
}

/**
 * Detect `sharedState.token = ...` style property assignment. The LHS
 * receiver is in the shared-state vocabulary and the LHS property name
 * is in the credential vocabulary. RHS is treated as the credential
 * source (or placeholder if it's a placeholder literal).
 */
function classifyPropertyAssignment(
  expr: ts.BinaryExpression,
  sf: ts.SourceFile,
  file: string,
  aliasMap: Map<string, string>,
  credentialBindings: ReadonlySet<string>,
): CredentialPropagationSite | null {
  if (!ts.isPropertyAccessExpression(expr.left)) return null;
  const recv = expr.left.expression;
  if (!ts.isIdentifier(recv)) return null;
  const recvRaw = recv.text.toLowerCase();
  const recvNorm = normalizeIdentifier(recvRaw);
  let receiverName: string;
  let kind: "direct" | "alias";
  if (SHARED_RECEIVER_SET.has(recvNorm)) {
    receiverName = recvNorm;
    kind = "direct";
  } else {
    const aliased = aliasMap.get(recvRaw);
    if (aliased && SHARED_RECEIVER_SET.has(aliased)) {
      receiverName = aliased;
      kind = "alias";
    } else {
      return null;
    }
  }
  const propRaw = expr.left.name.text.toLowerCase();
  const propNorm = normalizeIdentifier(propRaw);
  if (!CREDENTIAL_SET.has(propNorm)) return null;

  const rhs = expr.right;
  const rhsIsPlaceholder = isPlaceholderLiteral(rhs);
  const credentialSourceLocation = sourceLocation(sf, file, expr.left.name);
  const encoderWrapped = ts.isCallExpression(rhs) && isEncoderChain(rhs);
  const enclosing = findEnclosingFunction(expr);
  const enclosingLoc = enclosing ? sourceLocation(sf, file, enclosing) : null;
  const enclosingHasRedactor = enclosing ? scopeHasRedactor(enclosing) : false;

  void credentialBindings;
  return {
    location: sourceLocation(sf, file, expr),
    credentialSourceLocation,
    enclosingFunctionLocation: enclosingLoc,
    kind: encoderWrapped
      ? "encoder-wrapped-credential-write"
      : kind === "alias"
        ? "alias-credential-write"
        : "direct-credential-write",
    credentialName: propNorm,
    receiverName,
    writerMethod: "=",
    enclosingHasRedactor,
    rhsIsPlaceholder,
    observed: lineTextAt(sf, expr.getStart(sf)).trim().slice(0, 200),
  };
}

/**
 * Normalise an identifier by stripping underscores and hyphens. The
 * shared-state and credential vocabularies are stored without any
 * separators (e.g. `sharedstate`, `apikey`), so a caller may write
 * `shared_state`, `api-key`, `API_KEY` — all reduce to the canonical
 * form after lowercasing and stripping separators.
 */
function normalizeIdentifier(name: string): string {
  let out = "";
  for (let i = 0; i < name.length; i++) {
    const c = name[i];
    if (c === "_" || c === "-") continue;
    out += c;
  }
  return out;
}

interface SinkClassification {
  receiverName: string;     // lowercased, post-alias
  writerMethod: string;     // lowercased
  kind: "direct" | "alias" | "helper";
  helperLocation?: Location;
}

interface CredentialClassification {
  credentialName: string;          // lowercased
  credentialSourceLocation: Location;
  encoderWrapped: boolean;
  rhsIsPlaceholder: boolean;
}

function buildSite(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  sink: SinkClassification,
  cred: CredentialClassification,
): CredentialPropagationSite {
  const enclosing = findEnclosingFunction(call);
  const enclosingLoc: Location | null = enclosing
    ? sourceLocation(sf, file, enclosing)
    : null;
  const enclosingHasRedactor = enclosing
    ? scopeHasRedactor(enclosing)
    : false;

  let kind: K14EvidenceKind;
  if (cred.encoderWrapped) kind = "encoder-wrapped-credential-write";
  else if (sink.kind === "alias") kind = "alias-credential-write";
  else if (sink.kind === "helper") kind = "cross-function-helper-write";
  else kind = "direct-credential-write";

  return {
    location: sourceLocation(sf, file, call),
    credentialSourceLocation: cred.credentialSourceLocation,
    enclosingFunctionLocation: enclosingLoc,
    kind,
    credentialName: cred.credentialName,
    receiverName: sink.receiverName,
    writerMethod: sink.writerMethod,
    enclosingHasRedactor,
    rhsIsPlaceholder: cred.rhsIsPlaceholder,
    observed: lineTextAt(sf, call.getStart(sf)).trim().slice(0, 200),
  };
}

// ─── classification ────────────────────────────────────────────────────────

function classifySharedStateWriterCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  aliasMap: Map<string, string>,
): SinkClassification | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const method = call.expression.name.text.toLowerCase();
  if (!SHARED_WRITER_SET.has(method)) return null;
  const recv = call.expression.expression;
  if (!ts.isIdentifier(recv)) return null;
  const recvRaw = recv.text.toLowerCase();
  const recvNorm = normalizeIdentifier(recvRaw);
  if (SHARED_RECEIVER_SET.has(recvNorm)) {
    return { receiverName: recvNorm, writerMethod: method, kind: "direct" };
  }
  // alias-binding-resolution
  const aliased = aliasMap.get(recvRaw);
  if (aliased && SHARED_RECEIVER_SET.has(aliased)) {
    return { receiverName: aliased, writerMethod: method, kind: "alias" };
  }
  // suppress unused parameter warning
  void sf;
  return null;
}

function classifyHelperCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  helpers: Map<string, HelperInfo>,
): SinkClassification | null {
  if (!ts.isIdentifier(call.expression)) return null;
  const name = call.expression.text;
  const info = helpers.get(name);
  if (!info) return null;
  return {
    receiverName: info.receiverName,
    writerMethod: info.writerMethod,
    kind: "helper",
    helperLocation: sourceLocation(sf, info.file, info.fnNode),
  };
}

/**
 * Scan call arguments for a credential identifier. Recognises four
 * shapes:
 *   1. Identifier:     `set(token)` where `token` is a credential binding
 *      or a credential-named parameter / variable.
 *   2. Object literal: `set({ token })` / `set({ apiKey: x })`.
 *   3. Encoder wrapped: `set(Buffer.from(token).toString("base64"))`.
 *   4. String literal: `set("REPLACE_ME")` ⇒ rhsIsPlaceholder = true.
 */
function classifyCredentialArguments(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  credentialBindings: ReadonlySet<string>,
): CredentialClassification | null {
  let placeholderHit = false;
  // Detect a credential-named string literal in a key-value shape:
  //   store.set("secret", token)   → "secret" is the key, `token` is value
  //   store.set("apiKey", value)
  // When the first arg is a credential-named string and the second arg
  // is an identifier or other expression, treat the second arg as the
  // credential-bearing value and the first arg as the key label.
  const args = call.arguments;
  if (args.length >= 2 && isCredentialNamedStringLiteral(args[0])) {
    // Do not suppress — credential-named keys mean the value is a secret.
    const credName = normalizeIdentifier(
      ((args[0] as ts.StringLiteral).text || "").toLowerCase(),
    );
    // Second arg may still be a placeholder ("REPLACE_ME"), in which case
    // we leave the suppression path to handle it.
    if (isPlaceholderLiteral(args[1])) {
      return {
        credentialName: credName,
        credentialSourceLocation: sourceLocation(sf, "<inline>", args[1]),
        encoderWrapped: false,
        rhsIsPlaceholder: true,
      };
    }
    return {
      credentialName: credName,
      credentialSourceLocation: sourceLocation(sf, "<inline>", args[1]),
      encoderWrapped: ts.isCallExpression(args[1]) && isEncoderChain(args[1]),
      rhsIsPlaceholder: false,
    };
  }
  for (const arg of args) {
    const result = classifyExprForCredential(arg, sf, credentialBindings, false);
    if (result) {
      // If a credential is found alongside a placeholder elsewhere, the
      // credential wins — placeholder suppression only applies when the
      // ONLY argument is a placeholder.
      return result;
    }
    if (isPlaceholderLiteral(arg)) placeholderHit = true;
  }
  if (placeholderHit) {
    return {
      credentialName: "<placeholder>",
      credentialSourceLocation: sourceLocation(sf, "<inline>", args[0] ?? call),
      encoderWrapped: false,
      rhsIsPlaceholder: true,
    };
  }
  return null;
}

function isCredentialNamedStringLiteral(expr: ts.Expression): boolean {
  if (!ts.isStringLiteral(expr) && !ts.isNoSubstitutionTemplateLiteral(expr)) {
    return false;
  }
  const text = normalizeIdentifier(expr.text.toLowerCase());
  return CREDENTIAL_SET.has(text);
}

function classifyExprForCredential(
  expr: ts.Expression,
  sf: ts.SourceFile,
  credentialBindings: ReadonlySet<string>,
  encoderWrapped: boolean,
): CredentialClassification | null {
  // 1. Identifier
  if (ts.isIdentifier(expr)) {
    const rawName = expr.text.toLowerCase();
    const normName = normalizeIdentifier(rawName);
    if (
      CREDENTIAL_SET.has(normName) ||
      credentialBindings.has(rawName) ||
      credentialBindings.has(normName)
    ) {
      return {
        credentialName: normName,
        credentialSourceLocation: sourceLocation(sf, "<inline>", expr),
        encoderWrapped,
        rhsIsPlaceholder: false,
      };
    }
    return null;
  }
  // 2. Object literal: { token } / { token: x } / { apiKey: ... }
  if (ts.isObjectLiteralExpression(expr)) {
    for (const prop of expr.properties) {
      if (ts.isShorthandPropertyAssignment(prop)) {
        const rawName = prop.name.text.toLowerCase();
        const normName = normalizeIdentifier(rawName);
        if (
          CREDENTIAL_SET.has(normName) ||
          credentialBindings.has(rawName) ||
          credentialBindings.has(normName)
        ) {
          return {
            credentialName: normName,
            credentialSourceLocation: sourceLocation(sf, "<inline>", prop),
            encoderWrapped,
            rhsIsPlaceholder: false,
          };
        }
      } else if (ts.isPropertyAssignment(prop)) {
        const propNameNode = prop.name;
        let propRaw: string | null = null;
        if (ts.isIdentifier(propNameNode)) propRaw = propNameNode.text.toLowerCase();
        else if (ts.isStringLiteral(propNameNode)) propRaw = propNameNode.text.toLowerCase();
        const propName = propRaw ? normalizeIdentifier(propRaw) : null;
        if (propName && CREDENTIAL_SET.has(propName)) {
          return {
            credentialName: propName,
            credentialSourceLocation: sourceLocation(sf, "<inline>", prop),
            encoderWrapped,
            rhsIsPlaceholder: false,
          };
        }
        // also walk the value expression — `{ payload: token }`
        const valueResult = classifyExprForCredential(
          prop.initializer,
          sf,
          credentialBindings,
          encoderWrapped,
        );
        if (valueResult) return valueResult;
      }
    }
    return null;
  }
  // 3. Encoder wrapping — look through the call; encoder-passthrough-taint.
  if (ts.isCallExpression(expr)) {
    // A method chain like Buffer.from(token).toString("base64") is still an
    // encoder passthrough as long as ANY link in the chain is in the
    // encoder vocabulary. Walk the chain receiver-by-receiver.
    if (isEncoderChain(expr)) {
      // Walk the arguments of every call in the chain, plus the innermost
      // receiver identifier, looking for a credential.
      const inner = findCredentialInCallChain(expr, sf, credentialBindings);
      if (inner) return inner;
    }
    return null;
  }
  // 4. Property access:  token.value
  if (ts.isPropertyAccessExpression(expr)) {
    const inner = classifyExprForCredential(
      expr.expression,
      sf,
      credentialBindings,
      encoderWrapped,
    );
    if (inner) return inner;
    const propName = normalizeIdentifier(expr.name.text.toLowerCase());
    if (CREDENTIAL_SET.has(propName)) {
      return {
        credentialName: propName,
        credentialSourceLocation: sourceLocation(sf, "<inline>", expr),
        encoderWrapped,
        rhsIsPlaceholder: false,
      };
    }
  }
  return null;
}

/**
 * True if any call in the chain matches an encoder passthrough. Walks
 * from the outermost call down the receiver chain.
 */
function isEncoderChain(call: ts.CallExpression): boolean {
  let cur: ts.Node = call;
  while (cur) {
    if (ts.isCallExpression(cur)) {
      if (ts.isIdentifier(cur.expression)) {
        if (ENCODER_SET.has(cur.expression.text.toLowerCase())) return true;
      }
      if (ts.isPropertyAccessExpression(cur.expression)) {
        const method = cur.expression.name.text.toLowerCase();
        if (ENCODER_SET.has(method)) return true;
        const recv = cur.expression.expression;
        if (ts.isIdentifier(recv) && ENCODER_SET.has(recv.text.toLowerCase())) {
          return true;
        }
        cur = recv;
        continue;
      }
    } else if (ts.isPropertyAccessExpression(cur)) {
      cur = cur.expression;
      continue;
    }
    break;
  }
  return false;
}

/**
 * Walk every call in an encoder chain. For each call's arguments, check
 * for a credential expression. Also check the innermost identifier
 * receiver as a credential source (rare but valid: `token.toString()`).
 */
function findCredentialInCallChain(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  credentialBindings: ReadonlySet<string>,
): CredentialClassification | null {
  let cur: ts.Node = call;
  while (cur) {
    if (ts.isCallExpression(cur)) {
      for (const arg of cur.arguments) {
        const inner = classifyExprForCredential(arg, sf, credentialBindings, true);
        if (inner) return inner;
      }
      if (ts.isPropertyAccessExpression(cur.expression)) {
        cur = cur.expression.expression;
        continue;
      }
      break;
    }
    if (ts.isPropertyAccessExpression(cur)) {
      // property access chains: examine the name as a credential indicator
      const propName = cur.name.text.toLowerCase();
      if (CREDENTIAL_SET.has(propName)) {
        return {
          credentialName: propName,
          credentialSourceLocation: sourceLocation(sf, "<inline>", cur),
          encoderWrapped: true,
          rhsIsPlaceholder: false,
        };
      }
      cur = cur.expression;
      continue;
    }
    if (ts.isIdentifier(cur)) {
      const name = cur.text.toLowerCase();
      if (CREDENTIAL_SET.has(name) || credentialBindings.has(name)) {
        return {
          credentialName: name,
          credentialSourceLocation: sourceLocation(sf, "<inline>", cur),
          encoderWrapped: true,
          rhsIsPlaceholder: false,
        };
      }
    }
    break;
  }
  return null;
}

function isPlaceholderLiteral(expr: ts.Expression): boolean {
  if (ts.isStringLiteral(expr) || ts.isNoSubstitutionTemplateLiteral(expr)) {
    const t = expr.text.toLowerCase();
    if (PLACEHOLDER_SET.has(t)) return true;
    for (const placeholder of PLACEHOLDER_SET) {
      if (t.includes(placeholder)) return true;
    }
  }
  return false;
}

// ─── alias + credential binding pre-pass ───────────────────────────────────

function collectAliasesAndCredentials(
  sf: ts.SourceFile,
  aliasMap: Map<string, string>,
  credentialBindings: Set<string>,
): void {
  ts.forEachChild(sf, function visit(node) {
    // const s = sharedStore  ⇒  s -> sharedstore (normalised)
    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isIdentifier(node.name) && ts.isIdentifier(node.initializer)) {
        const lhs = node.name.text.toLowerCase();
        const rhsRaw = node.initializer.text.toLowerCase();
        const rhsNorm = normalizeIdentifier(rhsRaw);
        if (SHARED_RECEIVER_SET.has(rhsNorm)) {
          aliasMap.set(lhs, rhsNorm);
        }
      }
      // const token = ... ⇒ credential binding (accept raw + normalised)
      if (ts.isIdentifier(node.name)) {
        const rawName = node.name.text.toLowerCase();
        const normName = normalizeIdentifier(rawName);
        if (CREDENTIAL_SET.has(normName)) {
          credentialBindings.add(rawName);
          credentialBindings.add(normName);
        }
      }
    }
    // function parameters whose name is a credential
    if (ts.isParameter(node) && ts.isIdentifier(node.name)) {
      const rawName = node.name.text.toLowerCase();
      const normName = normalizeIdentifier(rawName);
      if (CREDENTIAL_SET.has(normName)) {
        credentialBindings.add(rawName);
        credentialBindings.add(normName);
      }
    }
    ts.forEachChild(node, visit);
  });
}

// ─── helper-function pre-pass ──────────────────────────────────────────────

interface HelperInfo {
  fnNode: ts.Node;
  file: string;
  receiverName: string;
  writerMethod: string;
}

function collectHelpers(sf: ts.SourceFile): Map<string, HelperInfo> {
  const helpers = new Map<string, HelperInfo>();
  ts.forEachChild(sf, function visit(node) {
    let fnName: string | null = null;
    let fnNode: ts.Node | null = null;
    if (ts.isFunctionDeclaration(node) && node.name) {
      fnName = node.name.text;
      fnNode = node;
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isFunctionExpression(node.initializer) || ts.isArrowFunction(node.initializer))
    ) {
      fnName = node.name.text;
      fnNode = node.initializer;
    }

    if (fnName && fnNode) {
      const sink = findInnerSharedStateSink(fnNode);
      if (sink) {
        helpers.set(fnName, {
          fnNode,
          file: sf.fileName,
          receiverName: sink.receiverName,
          writerMethod: sink.writerMethod,
        });
      }
    }
    ts.forEachChild(node, visit);
  });
  return helpers;
}

function findInnerSharedStateSink(
  fn: ts.Node,
): { receiverName: string; writerMethod: string } | null {
  let result: { receiverName: string; writerMethod: string } | null = null;
  function visit(n: ts.Node): void {
    if (result) return;
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const method = n.expression.name.text.toLowerCase();
      if (SHARED_WRITER_SET.has(method)) {
        const recv = n.expression.expression;
        if (ts.isIdentifier(recv)) {
          const recvName = normalizeIdentifier(recv.text.toLowerCase());
          if (SHARED_RECEIVER_SET.has(recvName)) {
            result = { receiverName: recvName, writerMethod: method };
            return;
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(fn, visit);
  return result;
}

// ─── mitigation: redactor in scope ─────────────────────────────────────────

function scopeHasRedactor(enclosing: ts.Node): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isCallExpression(n)) {
      // bare-call: redact(...)
      if (ts.isIdentifier(n.expression)) {
        if (REDACTOR_CALL_SET.has(n.expression.text.toLowerCase())) {
          found = true;
          return;
        }
      }
      // receiver.method: vault.seal(token) / kms.encrypt(token)
      if (ts.isPropertyAccessExpression(n.expression)) {
        const recv = n.expression.expression;
        const method = n.expression.name.text.toLowerCase();
        if (REDACTOR_CALL_SET.has(method)) {
          found = true;
          return;
        }
        if (ts.isIdentifier(recv)) {
          const recvName = recv.text.toLowerCase();
          const methods = REDACTOR_RECEIVER_METHODS[recvName];
          if (methods && methods[method]) {
            found = true;
            return;
          }
        }
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(enclosing, visit);
  return found;
}

// ─── helpers ───────────────────────────────────────────────────────────────

function detectTestFileStructurally(sf: ts.SourceFile): boolean {
  let topLevelRunnerCalls = 0;
  let topLevelItOrTest = 0;
  let hasRunnerImport = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      if (TEST_RUNNER_SET.has(stmt.moduleSpecifier.text)) hasRunnerImport = true;
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

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function lineTextAt(sf: ts.SourceFile, pos: number): string {
  const { line } = sf.getLineAndCharacterOfPosition(pos);
  const lines = sf.text.split("\n");
  return lines[line] ?? "";
}
