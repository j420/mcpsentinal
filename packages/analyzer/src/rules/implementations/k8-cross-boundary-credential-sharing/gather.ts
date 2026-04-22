/**
 * K8 — Cross-Boundary Credential Sharing: deterministic AST gatherer.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  CREDENTIAL_HEADER_KEYS,
  CREDENTIAL_NAME_TOKENS,
  EXEC_CALLEES,
  OUTBOUND_NETWORK_CALLEES,
  SHARED_STORE_CALLEES,
  TOKEN_EXCHANGE_TOKENS,
} from "./data/credential-vocabulary.js";

export type K8FactKind =
  | "header-forward"
  | "shared-store-write"
  | "exec-with-credential";

export interface K8Fact {
  kind: K8FactKind;
  location: Location;
  observed: string;
  credentialIdentifier: string;
  calleeName: string;
  file: string;
  hasTokenExchange: boolean;
}

export interface K8GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: K8Fact[];
}

export function gatherK8(context: AnalysisContext): K8GatherResult {
  const files = collectFiles(context);
  if (files.size === 0) return { mode: "absent", facts: [] };

  const allFacts: K8Fact[] = [];
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
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"');
  const hasSuite =
    text.includes("describe(") || text.includes("it(") || text.includes("test(");
  return hasRunner && hasSuite;
}

function scanFile(file: string, text: string): K8Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const hasTokenExchange = detectTokenExchange(sf);
  const facts: K8Fact[] = [];

  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const callee = resolveCalleeName(node);
      if (callee) {
        if (isOutboundNetworkCallee(callee)) {
          const h = detectHeaderForward(node, sf, file, callee, hasTokenExchange);
          if (h) facts.push(h);
        }
        if (isSharedStoreCallee(callee)) {
          const s = detectSharedStoreWrite(node, sf, file, callee, hasTokenExchange);
          if (s) facts.push(s);
        }
        if (isExecCallee(callee)) {
          const e = detectExecWithCredential(node, sf, file, callee, hasTokenExchange);
          if (e) facts.push(e);
        }
      }
    }
    ts.forEachChild(node, visit);
  });

  return dedupe(facts);
}

function detectTokenExchange(sf: ts.SourceFile): boolean {
  const text = sf.text;
  for (const tok of TOKEN_EXCHANGE_TOKENS) {
    if (text.includes(tok)) return true;
  }
  return false;
}

function resolveCalleeName(call: ts.CallExpression): string | null {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

function isOutboundNetworkCallee(name: string): boolean {
  return OUTBOUND_NETWORK_CALLEES.has(name);
}
function isSharedStoreCallee(name: string): boolean {
  return SHARED_STORE_CALLEES.has(name);
}
function isExecCallee(name: string): boolean {
  return EXEC_CALLEES.has(name);
}

function detectHeaderForward(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  callee: string,
  hasTokenExchange: boolean,
): K8Fact | null {
  let hit: { headerKey: string; credentialId: string } | null = null;
  const visit = (n: ts.Node): void => {
    if (hit) return;
    if (ts.isObjectLiteralExpression(n)) {
      for (const prop of n.properties) {
        if (!ts.isPropertyAssignment(prop)) continue;
        const key = propertyKeyText(prop.name);
        if (!key) continue;
        if (!CREDENTIAL_HEADER_KEYS.has(key)) continue;
        const credId = findCredentialNameInExpression(prop.initializer);
        if (credId) {
          hit = { headerKey: key, credentialId: credId };
          return;
        }
      }
    }
    n.forEachChild(visit);
  };
  call.forEachChild(visit);
  if (!hit) return null;
  const settled: { headerKey: string; credentialId: string } = hit;
  return {
    kind: "header-forward",
    location: locFromNode(sf, file, call),
    observed: call.getText(sf).slice(0, 220),
    credentialIdentifier: settled.credentialId,
    calleeName: callee,
    file,
    hasTokenExchange,
  };
}

function detectSharedStoreWrite(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  callee: string,
  hasTokenExchange: boolean,
): K8Fact | null {
  for (const arg of call.arguments) {
    const credId = findCredentialNameInExpression(arg);
    if (credId) {
      return {
        kind: "shared-store-write",
        location: locFromNode(sf, file, call),
        observed: call.getText(sf).slice(0, 220),
        credentialIdentifier: credId,
        calleeName: callee,
        file,
        hasTokenExchange,
      };
    }
  }
  return null;
}

function detectExecWithCredential(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  callee: string,
  hasTokenExchange: boolean,
): K8Fact | null {
  for (const arg of call.arguments) {
    const credId = findCredentialNameInExpression(arg);
    if (credId) {
      return {
        kind: "exec-with-credential",
        location: locFromNode(sf, file, call),
        observed: call.getText(sf).slice(0, 220),
        credentialIdentifier: credId,
        calleeName: callee,
        file,
        hasTokenExchange,
      };
    }
  }
  return null;
}

function findCredentialNameInExpression(expr: ts.Expression): string | null {
  let found: string | null = null;
  const visit = (n: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(n)) {
      if (matchesCredentialToken(n.text)) {
        found = n.text;
        return;
      }
    }
    if (ts.isPropertyAccessExpression(n)) {
      if (matchesCredentialToken(n.name.text)) {
        found = renderPropertyAccess(n);
        return;
      }
    }
    if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      if (n.text.toLowerCase().startsWith("bearer ")) {
        found = n.text.slice(0, 40);
        return;
      }
    }
    if (ts.isTemplateExpression(n)) {
      for (const span of n.templateSpans) {
        visit(span.expression);
        if (found) return;
      }
      return;
    }
    n.forEachChild(visit);
  };
  visit(expr);
  return found;
}

function renderPropertyAccess(node: ts.PropertyAccessExpression): string {
  const parts: string[] = [node.name.text];
  let cur: ts.Expression = node.expression;
  while (ts.isPropertyAccessExpression(cur)) {
    parts.unshift(cur.name.text);
    cur = cur.expression;
  }
  if (ts.isIdentifier(cur)) parts.unshift(cur.text);
  return parts.join(".");
}

function matchesCredentialToken(name: string): boolean {
  const lower = name.toLowerCase();
  for (const tok of CREDENTIAL_NAME_TOKENS) {
    if (lower.includes(tok)) return true;
  }
  return false;
}

function propertyKeyText(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

function locFromNode(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function dedupe(facts: K8Fact[]): K8Fact[] {
  const seen = new Set<string>();
  const out: K8Fact[] = [];
  for (const f of facts) {
    const k =
      f.location.kind === "source"
        ? `${f.kind}|${f.location.file}|${f.location.line}|${f.location.col ?? 0}|${f.credentialIdentifier}`
        : `${f.kind}|${f.credentialIdentifier}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}
