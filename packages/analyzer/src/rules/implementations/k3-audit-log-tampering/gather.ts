/**
 * K3 — Audit Log Tampering: deterministic AST fact gatherer.
 *
 * Four fact kinds:
 *   - read-filter-write  round-trip read→transform→write on audit path.
 *   - inplace-shell      `sed -i` / `perl -i` on an audit path.
 *   - rw-mode-open       `fs.open(..., "r+"|"w+"|"a+")` on an audit path.
 *   - timestamp-forgery  `utimes(...)` on an audit path.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  AUDIT_PATH_SUBSTRINGS,
  INPLACE_OPEN_FLAGS,
  INPLACE_SHELL_TOKENS,
  REDACTION_EXCLUSION_TOKENS,
  TAMPER_TRANSFORM_TOKENS,
  TIMESTAMP_FORGERY_CALLEES,
} from "./data/audit-vocabulary.js";

export type K3FactKind =
  | "read-filter-write"
  | "inplace-shell"
  | "rw-mode-open"
  | "timestamp-forgery";

export interface K3Fact {
  kind: K3FactKind;
  location: Location;
  observed: string;
  auditPath: string;
  operation: string;
  file: string;
  readLocation: Location | null;
  writeLocation: Location | null;
  appendOnlyElsewhere: boolean;
}

export interface K3GatherResult {
  mode: "absent" | "test-file" | "facts";
  facts: K3Fact[];
}

export function gatherK3(context: AnalysisContext): K3GatherResult {
  const files = collectFiles(context);
  if (files.size === 0) return { mode: "absent", facts: [] };

  const allFacts: K3Fact[] = [];
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

function scanFile(file: string, text: string): K3Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const appendOnlyElsewhere = detectAppendOnlyFlags(sf);
  const facts: K3Fact[] = [];

  const reads: CallRecord[] = [];
  const writes: CallRecord[] = [];
  ts.forEachChild(sf, function visit(node) {
    if (ts.isCallExpression(node)) {
      const shellFact = detectInplaceShellInCall(node, sf, file, appendOnlyElsewhere);
      if (shellFact) facts.push(shellFact);

      const callee = resolveCalleeName(node.expression);
      if (!callee) {
        ts.forEachChild(node, visit);
        return;
      }

      const rwFact = detectRwModeOpen(node, callee, sf, file, appendOnlyElsewhere);
      if (rwFact) facts.push(rwFact);

      const tsFact = detectTimestampForgery(node, callee, sf, file, appendOnlyElsewhere);
      if (tsFact) facts.push(tsFact);

      if (isReadCallee(callee)) {
        const match = argAuditPath(node);
        if (match) reads.push({ node, auditPath: match });
      }
      if (isWriteCallee(callee)) {
        const match = argAuditPath(node);
        if (match) writes.push({ node, auditPath: match });
      }
    }

    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const literalFact = detectInplaceShellInLiteral(node, sf, file, appendOnlyElsewhere);
      if (literalFact) facts.push(literalFact);
    }

    ts.forEachChild(node, visit);
  });

  for (const r of reads) {
    for (const w of writes) {
      if (r.auditPath !== w.auditPath) continue;
      if (w.node.getStart(sf) <= r.node.getStart(sf)) continue;
      if (!transformBetween(sf, r.node, w.node)) continue;
      if (redactionContext(sf, r.node) || redactionContext(sf, w.node)) continue;

      const readLoc = locFromNode(sf, file, r.node);
      const writeLoc = locFromNode(sf, file, w.node);
      facts.push({
        kind: "read-filter-write",
        location: writeLoc,
        observed:
          `read ${r.node.getText(sf).slice(0, 80)} → write ${w.node
            .getText(sf)
            .slice(0, 80)}`,
        auditPath: r.auditPath,
        operation: "read-filter-write round-trip",
        file,
        readLocation: readLoc,
        writeLocation: writeLoc,
        appendOnlyElsewhere,
      });
      break;
    }
  }

  return facts;
}

interface CallRecord {
  node: ts.CallExpression;
  auditPath: string;
}

const READ_CALLEE_NAMES = new Set<string>(["readFile", "readFileSync", "createReadStream"]);
const WRITE_CALLEE_NAMES = new Set<string>([
  "writeFile",
  "writeFileSync",
  "createWriteStream",
  "appendFile",
  "appendFileSync",
]);

function isReadCallee(name: string): boolean {
  return READ_CALLEE_NAMES.has(name);
}
function isWriteCallee(name: string): boolean {
  return WRITE_CALLEE_NAMES.has(name);
}

function resolveCalleeName(expr: ts.Expression): string | null {
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr) && ts.isIdentifier(expr.name)) {
    return expr.name.text;
  }
  return null;
}

function argAuditPath(call: ts.CallExpression): string | null {
  const first = call.arguments[0];
  if (!first) return null;
  return findAuditSubstring(first.getText());
}

function findAuditSubstring(text: string): string | null {
  for (const sub of AUDIT_PATH_SUBSTRINGS) {
    if (text.toLowerCase().includes(sub)) return sub;
  }
  return null;
}

function locFromNode(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const { line, character } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function detectAppendOnlyFlags(sf: ts.SourceFile): boolean {
  let seen = false;
  ts.forEachChild(sf, function visit(node) {
    if (seen) return;
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const text = node.text;
      if (text === "a" || text === "a+") seen = true;
      if (text.includes("O_APPEND")) seen = true;
    }
    ts.forEachChild(node, visit);
  });
  return seen;
}

function transformBetween(
  sf: ts.SourceFile,
  from: ts.CallExpression,
  to: ts.CallExpression,
): boolean {
  const text = sf.text.slice(from.getEnd(), to.getStart(sf));
  for (const tok of TAMPER_TRANSFORM_TOKENS) {
    if (text.includes(`.${tok}(`)) return true;
  }
  return false;
}

function redactionContext(sf: ts.SourceFile, node: ts.Node): boolean {
  let cur: ts.Node | undefined = node;
  while (cur && !ts.isFunctionLike(cur)) cur = cur.parent;
  const name = (cur && (cur as ts.FunctionLikeDeclaration).name)
    ? ((cur as ts.FunctionLikeDeclaration).name as ts.Identifier).text.toLowerCase()
    : "";
  if (tokensIntersect(name, REDACTION_EXCLUSION_TOKENS)) return true;
  const start = Math.max(0, node.getStart(sf) - 120);
  const context = sf.text.slice(start, node.getStart(sf)).toLowerCase();
  return tokensIntersect(context, REDACTION_EXCLUSION_TOKENS);
}

function tokensIntersect(text: string, tokens: ReadonlySet<string>): boolean {
  for (const t of tokens) {
    if (text.includes(t)) return true;
  }
  return false;
}

function detectInplaceShellInCall(
  call: ts.CallExpression,
  sf: ts.SourceFile,
  file: string,
  appendOnlyElsewhere: boolean,
): K3Fact | null {
  for (const arg of call.arguments) {
    if (!ts.isStringLiteral(arg) && !ts.isNoSubstitutionTemplateLiteral(arg)) continue;
    const text = arg.text;
    const hit = matchInplaceShell(text);
    if (!hit) continue;
    return {
      kind: "inplace-shell",
      location: locFromNode(sf, file, call),
      observed: call.getText(sf).slice(0, 220),
      auditPath: hit.path,
      operation: hit.tool,
      file,
      readLocation: null,
      writeLocation: null,
      appendOnlyElsewhere,
    };
  }
  return null;
}

function detectInplaceShellInLiteral(
  lit: ts.StringLiteralLike,
  sf: ts.SourceFile,
  file: string,
  appendOnlyElsewhere: boolean,
): K3Fact | null {
  const hit = matchInplaceShell(lit.text);
  if (!hit) return null;
  return {
    kind: "inplace-shell",
    location: locFromNode(sf, file, lit),
    observed: lit.text.slice(0, 220),
    auditPath: hit.path,
    operation: hit.tool,
    file,
    readLocation: null,
    writeLocation: null,
    appendOnlyElsewhere,
  };
}

function matchInplaceShell(text: string): { tool: string; path: string } | null {
  const lower = text.toLowerCase();
  for (const tool of INPLACE_SHELL_TOKENS) {
    if (!lower.includes(tool)) continue;
    const path = findAuditSubstring(text);
    if (path) return { tool, path };
  }
  return null;
}

function detectRwModeOpen(
  call: ts.CallExpression,
  callee: string,
  sf: ts.SourceFile,
  file: string,
  appendOnlyElsewhere: boolean,
): K3Fact | null {
  if (callee !== "open" && callee !== "openSync" && callee !== "createReadStream") {
    return null;
  }
  const path = argAuditPath(call);
  if (!path) return null;

  const flagArg = call.arguments[1];
  if (!flagArg) return null;
  let flagText: string | null = null;
  if (ts.isStringLiteral(flagArg)) flagText = flagArg.text;
  else if (ts.isObjectLiteralExpression(flagArg)) {
    for (const prop of flagArg.properties) {
      if (
        ts.isPropertyAssignment(prop) &&
        ts.isIdentifier(prop.name) &&
        prop.name.text === "flags" &&
        ts.isStringLiteral(prop.initializer)
      ) {
        flagText = prop.initializer.text;
      }
    }
  }
  if (flagText === null) return null;
  if (!INPLACE_OPEN_FLAGS.has(flagText)) return null;

  return {
    kind: "rw-mode-open",
    location: locFromNode(sf, file, call),
    observed: call.getText(sf).slice(0, 220),
    auditPath: path,
    operation: `open flag "${flagText}"`,
    file,
    readLocation: null,
    writeLocation: null,
    appendOnlyElsewhere,
  };
}

function detectTimestampForgery(
  call: ts.CallExpression,
  callee: string,
  sf: ts.SourceFile,
  file: string,
  appendOnlyElsewhere: boolean,
): K3Fact | null {
  if (!TIMESTAMP_FORGERY_CALLEES.has(callee)) return null;
  const path = argAuditPath(call);
  if (!path) return null;
  return {
    kind: "timestamp-forgery",
    location: locFromNode(sf, file, call),
    observed: call.getText(sf).slice(0, 220),
    auditPath: path,
    operation: callee,
    file,
    readLocation: null,
    writeLocation: null,
    appendOnlyElsewhere,
  };
}
