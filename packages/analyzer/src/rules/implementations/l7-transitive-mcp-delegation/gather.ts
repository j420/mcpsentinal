/**
 * L7 — Transitive MCP Delegation: deterministic AST fact gatherer.
 *
 * Emits facts at three semantic levels:
 *
 *   1. dual-sdk-import        both a server and a client / proxy MCP
 *                             import exist in the same file.
 *   2. client-construction    `new Client(...)` / `new XxxTransport(...)`
 *                             using a constructor imported from the MCP
 *                             client SDK, or a dynamic `import()` call
 *                             whose specifier resolves to the client SDK.
 *   3. credential-forwarding  an identifier taken from an incoming
 *                             request object (`req.headers`, `request.auth`,
 *                             `ctx.request.*`) is used in the arguments
 *                             of a call whose receiver is a detected
 *                             client binding.
 *
 * Zero regex literals outside `./data/`. Test files (identified by
 * structural shape, not filename) are excluded.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  MCP_CLIENT_SDK_SUBSTRINGS,
  MCP_SERVER_SDK_SUBSTRINGS,
  MCP_PROXY_FRAMEWORKS,
  CLIENT_TRANSPORT_CLASSES,
  CREDENTIAL_FORWARDING_HINTS,
} from "./data/delegation-vocabulary.js";

// ─── Public types ──────────────────────────────────────────────────────────

export type L7FactKind =
  | "dual-sdk-import"
  | "client-construction"
  | "credential-forwarding";

export interface L7Fact {
  kind: L7FactKind;
  /** source-kind Location — file:line:col */
  location: Location;
  /** Verbatim dangerous fragment. */
  observed: string;
  /** Which file the fact lives in (mirrors location.file when kind=source). */
  file: string;
  /** For dual-sdk-import: the specific import specifier that triggered. */
  specifier: string | null;
  /** For client-construction: the constructor identifier. */
  constructorName: string | null;
  /** For credential-forwarding: the incoming-request identifier name. */
  credentialRef: string | null;
  /** The companion client-import location for this file, when known. */
  clientImportLocation: Location | null;
  /** The companion server-import location for this file, when known. */
  serverImportLocation: Location | null;
}

export interface L7GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: L7Fact[];
}

// ─── Gather entry point ────────────────────────────────────────────────────

export function gatherL7(context: AnalysisContext): L7GatherResult {
  const files = collectFiles(context);
  if (files.size === 0) return { mode: "absent", facts: [] };

  const allFacts: L7Fact[] = [];
  let anyScanned = false;
  for (const [file, text] of files) {
    if (isTestFileShape(file, text)) continue;
    anyScanned = true;
    allFacts.push(...scanFile(file, text));
  }
  if (!anyScanned) return { mode: "test-file", facts: [] };
  return { mode: allFacts.length > 0 ? "facts" : "absent", facts: allFacts };
}

function collectFiles(context: AnalysisContext): Map<string, string> {
  const out = new Map<string, string>();
  if (context.source_files && context.source_files.size > 0) {
    for (const [k, v] of context.source_files) out.set(k, v);
    return out;
  }
  if (context.source_code) out.set("<concatenated-source>", context.source_code);
  return out;
}

function isTestFileShape(file: string, text: string): boolean {
  if (
    file.endsWith(".test.ts") ||
    file.endsWith(".spec.ts") ||
    file.endsWith(".test.js") ||
    file.endsWith(".spec.js") ||
    file.includes("__tests__/") ||
    file.includes("__fixtures__/")
  ) {
    return true;
  }
  // Structural — runner import plus a top-level describe/it/test call.
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"') ||
    text.includes("require('vitest')");
  const hasSuite =
    text.includes("describe(") || text.includes("it(") || text.includes("test(");
  return hasRunner && hasSuite;
}

// ─── File scan ─────────────────────────────────────────────────────────────

interface FileScanState {
  file: string;
  /** Client-side MCP SDK / proxy imports observed in this file. */
  clientImports: ClientImportRecord[];
  /** Server-side MCP SDK imports observed in this file. */
  serverImports: ImportRecord[];
  /** Local binding → import record for constructor resolution. */
  localBindings: Map<string, ClientImportRecord>;
  /** Incoming-request binding names (e.g. `req`, `request`, `ctx`). */
  incomingRequestBindings: Set<string>;
}

interface ImportRecord {
  location: Location;
  specifier: string;
}

interface ClientImportRecord extends ImportRecord {
  /** Which transport / `Client` class this binding refers to. */
  imported: string;
  /** Whether this import is a proxy-framework import (MCP_PROXY_FRAMEWORKS). */
  proxyFramework: boolean;
}

function scanFile(file: string, text: string): L7Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const state: FileScanState = {
    file,
    clientImports: [],
    serverImports: [],
    localBindings: new Map(),
    incomingRequestBindings: new Set(),
  };

  // Pass 1: collect import declarations + their bindings.
  for (const stmt of sf.statements) {
    classifyImport(stmt, sf, file, state);
  }

  const facts: L7Fact[] = [];

  // Pass 2: walk the tree collecting dynamic imports, constructions,
  // and credential-forwarding candidates.
  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const dyn = classifyDynamicImport(node, sf, file);
      if (dyn) {
        if (dyn.kind === "client") {
          state.clientImports.push({
            location: sourceLocation(sf, file, node),
            specifier: dyn.specifier,
            imported: "<dynamic>",
            proxyFramework: dyn.proxy,
          });
        } else {
          state.serverImports.push({
            location: sourceLocation(sf, file, node),
            specifier: dyn.specifier,
          });
        }
      }
    }

    // Track bindings of incoming-request arrow-function parameters, e.g.
    // `app.post("/tool", (req, res) => ...)` / `async (request, ctx) => {}`.
    if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
      for (const p of node.parameters) {
        if (ts.isIdentifier(p.name)) {
          const n = p.name.text;
          if (isIncomingRequestName(n)) state.incomingRequestBindings.add(n);
        }
      }
    }

    // Detect client-construction via NewExpression.
    if (ts.isNewExpression(node)) {
      const ctorFact = detectClientConstruction(node, sf, file, state);
      if (ctorFact) facts.push(ctorFact);
    }

    // Detect credential-forwarding: call whose receiver is a known
    // client-binding and whose arguments reference an incoming-request
    // credential.
    if (ts.isCallExpression(node)) {
      const fwdFact = detectCredentialForwarding(node, sf, file, state);
      if (fwdFact) facts.push(fwdFact);
    }

    ts.forEachChild(node, visit);
  });

  // Dual-SDK-import fact — emitted once per file when both a client
  // (or proxy) import and a server import coexist.
  const hasClient = state.clientImports.length > 0;
  const hasServer = state.serverImports.length > 0;
  if (hasClient && hasServer) {
    const primaryClient = state.clientImports[0];
    const primaryServer = state.serverImports[0];
    facts.unshift({
      kind: "dual-sdk-import",
      location: primaryClient.location,
      observed:
        `client: ${primaryClient.specifier}  |  server: ${primaryServer.specifier}`,
      file,
      specifier: primaryClient.specifier,
      constructorName: null,
      credentialRef: null,
      clientImportLocation: primaryClient.location,
      serverImportLocation: primaryServer.location,
    });
  }

  // If we found a client-construction but NO server import was present,
  // it is still a finding (the rule fires on transitive delegation even
  // in a non-dual-SDK file — e.g. a proxy framework import alone). We
  // keep these facts as-is.
  return facts;
}

// ─── Import classification ─────────────────────────────────────────────────

function classifyImport(
  stmt: ts.Statement,
  sf: ts.SourceFile,
  file: string,
  state: FileScanState,
): void {
  if (!ts.isImportDeclaration(stmt)) return;
  if (!ts.isStringLiteral(stmt.moduleSpecifier)) return;
  const spec = stmt.moduleSpecifier.text;
  const isClient = isClientSpecifier(spec);
  const isServer = isServerSpecifier(spec);
  const isProxy = isProxyFramework(spec);

  if (!isClient && !isServer && !isProxy) return;

  const loc = sourceLocation(sf, file, stmt);
  if (isServer) {
    state.serverImports.push({ location: loc, specifier: spec });
    // A module can export both client and server surfaces; keep going
    // to register client bindings too if present on the same statement.
  }

  if (isClient || isProxy) {
    recordClientBindings(stmt, loc, spec, isProxy, state);
  }
}

function recordClientBindings(
  stmt: ts.ImportDeclaration,
  loc: Location,
  specifier: string,
  proxy: boolean,
  state: FileScanState,
): void {
  const clause = stmt.importClause;
  const collect = (name: string, imported: string): void => {
    const record: ClientImportRecord = {
      location: loc,
      specifier,
      imported,
      proxyFramework: proxy,
    };
    state.clientImports.push(record);
    state.localBindings.set(name, record);
  };

  if (!clause) {
    // Side-effect-only import — we still record the specifier so dual-SDK works.
    state.clientImports.push({
      location: loc,
      specifier,
      imported: "<side-effect>",
      proxyFramework: proxy,
    });
    return;
  }
  if (clause.name) collect(clause.name.text, clause.name.text);
  if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
    collect(clause.namedBindings.name.text, clause.namedBindings.name.text);
  }
  if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
    for (const el of clause.namedBindings.elements) {
      const importedName = el.propertyName ? el.propertyName.text : el.name.text;
      collect(el.name.text, importedName);
    }
  }
}

function classifyDynamicImport(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  _file: string,
): { kind: "client" | "server"; specifier: string; proxy: boolean } | null {
  // import("...")
  if (call.expression.kind === ts.SyntaxKind.ImportKeyword) {
    const arg = call.arguments[0];
    if (!arg || !ts.isStringLiteral(arg)) return null;
    const spec = arg.text;
    if (isClientSpecifier(spec)) return { kind: "client", specifier: spec, proxy: false };
    if (isProxyFramework(spec)) return { kind: "client", specifier: spec, proxy: true };
    if (isServerSpecifier(spec)) return { kind: "server", specifier: spec, proxy: false };
    return null;
  }
  // require("...")
  if (
    ts.isIdentifier(call.expression) &&
    call.expression.text === "require" &&
    call.arguments.length === 1 &&
    ts.isStringLiteral(call.arguments[0])
  ) {
    const spec = (call.arguments[0] as ts.StringLiteral).text;
    if (isClientSpecifier(spec)) return { kind: "client", specifier: spec, proxy: false };
    if (isProxyFramework(spec)) return { kind: "client", specifier: spec, proxy: true };
    if (isServerSpecifier(spec)) return { kind: "server", specifier: spec, proxy: false };
    void sf;
  }
  return null;
}

function isClientSpecifier(spec: string): boolean {
  for (const sub of MCP_CLIENT_SDK_SUBSTRINGS) {
    if (spec.includes(sub)) return true;
  }
  return false;
}

function isServerSpecifier(spec: string): boolean {
  for (const sub of MCP_SERVER_SDK_SUBSTRINGS) {
    if (spec.includes(sub)) return true;
  }
  return false;
}

function isProxyFramework(spec: string): boolean {
  for (const pkg of MCP_PROXY_FRAMEWORKS) {
    if (spec === pkg) return true;
    if (spec.startsWith(`${pkg}/`)) return true;
  }
  return false;
}

// ─── Construction detection ────────────────────────────────────────────────

function detectClientConstruction(
  node: ts.NewExpression,
  sf: ts.SourceFile,
  file: string,
  state: FileScanState,
): L7Fact | null {
  const ctorName = resolveIdentifier(node.expression);
  if (!ctorName) return null;
  const fromClientImport = state.localBindings.get(ctorName);
  const isTransportClass = CLIENT_TRANSPORT_CLASSES.has(ctorName);
  if (!fromClientImport && !isTransportClass) return null;

  if (isTransportClass && !fromClientImport && state.clientImports.length === 0) {
    return null;
  }

  // L7 is a *transitive*-delegation rule. A construction inside a file
  // that does NOT also import the MCP server SDK is just a plain client
  // application — not a proxy. Skip unless this file imports the server
  // SDK OR a proxy framework (which encapsulates the server side).
  const hasServerSide =
    state.serverImports.length > 0 ||
    state.clientImports.some((ci) => ci.proxyFramework);
  if (!hasServerSide) return null;

  const primaryClient = state.clientImports[0] ?? null;
  const primaryServer = state.serverImports[0] ?? null;

  return {
    kind: "client-construction",
    location: sourceLocation(sf, file, node),
    observed: node.getText(sf).slice(0, 240),
    file,
    specifier: fromClientImport?.specifier ?? primaryClient?.specifier ?? null,
    constructorName: ctorName,
    credentialRef: null,
    clientImportLocation: fromClientImport?.location ?? primaryClient?.location ?? null,
    serverImportLocation: primaryServer?.location ?? null,
  };
}

// ─── Credential forwarding detection ───────────────────────────────────────

function detectCredentialForwarding(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  state: FileScanState,
): L7Fact | null {
  if (!ts.isPropertyAccessExpression(call.expression)) return null;
  const receiver = call.expression.expression;
  if (!ts.isIdentifier(receiver)) return null;
  if (!state.localBindings.has(receiver.text) && !looksLikeClientVariable(receiver.text)) {
    return null;
  }

  // Transitive-delegation scope guard — the forwarding fact is only
  // meaningful when this module is also the server surface a user
  // approved. Without a server-side import in the same file, the
  // forwarding is a normal client app's auth flow.
  const hasServerSide =
    state.serverImports.length > 0 ||
    state.clientImports.some((ci) => ci.proxyFramework);
  if (!hasServerSide) return null;

  const credRef = findForwardedCredential(call, state.incomingRequestBindings);
  if (!credRef) return null;

  const primaryClient = state.clientImports[0] ?? null;
  const primaryServer = state.serverImports[0] ?? null;

  return {
    kind: "credential-forwarding",
    location: sourceLocation(sf, file, call),
    observed: call.getText(sf).slice(0, 240),
    file,
    specifier: primaryClient?.specifier ?? null,
    constructorName: null,
    credentialRef: credRef,
    clientImportLocation: primaryClient?.location ?? null,
    serverImportLocation: primaryServer?.location ?? null,
  };
}

function findForwardedCredential(
  node: ts.Node,
  incomingBindings: ReadonlySet<string>,
): string | null {
  let found: string | null = null;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isPropertyAccessExpression(n)) {
      const root = extractRootIdentifier(n);
      if (root && incomingBindings.has(root)) {
        const tail = n.name.text;
        const rootChain = getPropertyChain(n);
        if (
          CREDENTIAL_FORWARDING_HINTS.has(tail) ||
          rootChain.some((seg) => CREDENTIAL_FORWARDING_HINTS.has(seg))
        ) {
          found = `${root}.${rootChain.join(".")}`;
        }
      }
    }
    n.forEachChild(visit);
  };
  node.forEachChild(visit);
  return found;
}

function extractRootIdentifier(expr: ts.PropertyAccessExpression): string | null {
  let cur: ts.Expression = expr.expression;
  while (ts.isPropertyAccessExpression(cur)) cur = cur.expression;
  return ts.isIdentifier(cur) ? cur.text : null;
}

function getPropertyChain(expr: ts.PropertyAccessExpression): string[] {
  const out: string[] = [];
  let cur: ts.Expression = expr;
  while (ts.isPropertyAccessExpression(cur)) {
    out.unshift(cur.name.text);
    cur = cur.expression;
  }
  return out;
}

function looksLikeClientVariable(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === "client" ||
    lower.endsWith("client") ||
    lower === "upstream" ||
    lower === "proxy"
  );
}

function isIncomingRequestName(name: string): boolean {
  const lower = name.toLowerCase();
  return (
    lower === "req" ||
    lower === "request" ||
    lower === "ctx" ||
    lower === "context" ||
    lower === "incoming"
  );
}

function resolveIdentifier(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

function sourceLocation(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}
