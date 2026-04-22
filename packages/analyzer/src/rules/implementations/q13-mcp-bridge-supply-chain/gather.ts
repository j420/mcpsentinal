/**
 * Q13 gather — AST scan for unpinned MCP bridge invocations.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  BRIDGE_PACKAGE_NAMES,
  FETCH_EXEC_COMMANDS,
  LOOSE_VERSION_MARKERS,
} from "./data/vocabulary.js";

const BRIDGE_NAMES: ReadonlySet<string> = new Set(Object.keys(BRIDGE_PACKAGE_NAMES));
const FETCH_EXEC_SET: ReadonlySet<string> = new Set(Object.keys(FETCH_EXEC_COMMANDS));
const LOOSE_RANGE_SET: ReadonlySet<string> = new Set(Object.keys(LOOSE_VERSION_MARKERS));

export type BridgeHitKind =
  | "shell-literal"          // "npx mcp-remote"
  | "child-process-args"     // spawn('npx', ['mcp-remote'])
  | "manifest-range";        // { "mcp-remote": "^1.0.0" }

export interface BridgeSupplyChainSite {
  kind: BridgeHitKind;
  packageName: string;
  /** Snippet as observed. */
  observed: string;
  location: Location;
}

export interface Q13Gathered {
  sites: BridgeSupplyChainSite[];
}

export function gatherQ13(context: AnalysisContext): Q13Gathered {
  const text = context.source_code;
  if (!text) return { sites: [] };
  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  const sites: BridgeSupplyChainSite[] = [];

  ts.forEachChild(sf, function visit(node) {
    // Shell-literal string: "npx mcp-remote ..."
    if (
      (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) &&
      !isTemplateHead(node)
    ) {
      const pkgHit = classifyShellLiteral(node.text);
      if (pkgHit) {
        sites.push({
          kind: "shell-literal",
          packageName: pkgHit,
          observed: node.text.slice(0, 200),
          location: sourceLocation(sf, node),
        });
      }
    }
    // child_process call: spawn('npx', ['mcp-remote']) / exec('npx mcp-proxy ...')
    if (ts.isCallExpression(node)) {
      const hit = classifyChildProcessCall(node);
      if (hit) {
        sites.push({
          ...hit,
          location: sourceLocation(sf, node),
        });
      }
    }
    // Manifest range: { "mcp-remote": "^1.0.0" } inside an object literal
    if (ts.isPropertyAssignment(node)) {
      const propName = propertyName(node.name);
      if (propName && BRIDGE_NAMES.has(propName)) {
        const rhs = node.initializer;
        if (ts.isStringLiteral(rhs) || ts.isNoSubstitutionTemplateLiteral(rhs)) {
          if (isLooseRange(rhs.text)) {
            sites.push({
              kind: "manifest-range",
              packageName: propName,
              observed: `"${propName}": "${rhs.text}"`,
              location: sourceLocation(sf, node),
            });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  });

  return { sites };
}

function classifyShellLiteral(text: string): string | null {
  // Hand-tokenise the shell literal: first word, then search for a
  // bridge-package argument without a version pin.
  const words = splitByWhitespace(text);
  if (words.length < 2) return null;
  const head = words[0].toLowerCase();
  if (!FETCH_EXEC_SET.has(head)) return null;
  for (let i = 1; i < words.length; i++) {
    const arg = words[i];
    if (arg.startsWith("-")) continue; // skip options
    const bare = stripScopeIfNeeded(arg);
    const atIdx = bare.indexOf("@");
    // If there's a version pin, skip (pinned invocation is OK). For scoped
    // packages like @modelcontextprotocol/sdk, the leading @ is the scope,
    // not a version; atIdx 0 means "scoped with no version" (not pinned).
    if (atIdx > 0) {
      const name = bare.slice(0, atIdx).toLowerCase();
      if (BRIDGE_NAMES.has(name)) {
        // pinned — not a finding
        return null;
      }
      continue;
    }
    // No @ sign OR it's at position 0 (scoped package with no version)
    const name = bare.toLowerCase();
    if (BRIDGE_NAMES.has(name)) return name;
  }
  return null;
}

function stripScopeIfNeeded(arg: string): string {
  return arg;
}

function splitByWhitespace(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
      if (cur.length > 0) {
        out.push(cur);
        cur = "";
      }
      continue;
    }
    cur += s[i];
  }
  if (cur.length > 0) out.push(cur);
  return out;
}

function classifyChildProcessCall(
  call: ts.CallExpression,
): { kind: BridgeHitKind; packageName: string; observed: string } | null {
  let method: string | null = null;
  if (ts.isPropertyAccessExpression(call.expression)) {
    method = call.expression.name.text.toLowerCase();
  } else if (ts.isIdentifier(call.expression)) {
    method = call.expression.text.toLowerCase();
  }
  if (!method) return null;
  const ok =
    method === "spawn" ||
    method === "spawnsync" ||
    method === "exec" ||
    method === "execsync" ||
    method === "execfile" ||
    method === "execfilesync";
  if (!ok) return null;

  const firstArg = call.arguments[0];
  if (!firstArg) return null;
  if (!ts.isStringLiteral(firstArg) && !ts.isNoSubstitutionTemplateLiteral(firstArg)) return null;
  const programRaw = firstArg.text;
  // If program is itself a full shell-literal containing a bridge
  // package, classify through shell-literal path.
  const shellPkg = classifyShellLiteral(programRaw);
  if (shellPkg) {
    return {
      kind: "child-process-args",
      packageName: shellPkg,
      observed: `spawn(${JSON.stringify(programRaw)})`,
    };
  }
  if (!FETCH_EXEC_SET.has(programRaw.toLowerCase())) return null;
  // Inspect the second argument (array of strings) for a bridge
  // package without a version pin.
  const second = call.arguments[1];
  if (!second) return null;
  if (ts.isArrayLiteralExpression(second)) {
    for (const el of second.elements) {
      if (!ts.isStringLiteral(el) && !ts.isNoSubstitutionTemplateLiteral(el)) continue;
      const arg = el.text;
      if (arg.startsWith("-")) continue;
      const atIdx = arg.indexOf("@");
      if (atIdx > 0) {
        const name = arg.slice(0, atIdx).toLowerCase();
        if (BRIDGE_NAMES.has(name)) return null; // pinned
        continue;
      }
      const name = arg.toLowerCase();
      if (BRIDGE_NAMES.has(name)) {
        return {
          kind: "child-process-args",
          packageName: name,
          observed: `spawn("${programRaw}", [..., "${arg}", ...])`,
        };
      }
    }
  }
  return null;
}

function isLooseRange(version: string): boolean {
  const trimmed = version.trim();
  if (trimmed.length === 0) return true;
  if (LOOSE_RANGE_SET.has(trimmed)) return true;
  if (trimmed.startsWith("^") || trimmed.startsWith("~")) return true;
  return false;
}

function propertyName(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
  return null;
}

function isTemplateHead(node: ts.Node): boolean {
  // Skip template heads (handled separately by the tagged template
  // literal flow). A NoSubstitutionTemplateLiteral is node-safe.
  return ts.isTemplateHead(node);
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
