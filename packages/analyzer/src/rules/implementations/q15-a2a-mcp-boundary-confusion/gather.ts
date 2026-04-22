/**
 * Q15 gather — AST walk for (A2A protocol surface read) × (MCP context sink)
 * within the same enclosing function.
 *
 * Zero regex. Honest-refusal gate: if no A2A surface appears in
 * the entire source file, return immediately.
 *
 * Five A2A categories tracked: AgentCard, Part, Push, Discovery,
 * and A2A_URI (a2a:// string literal).
 *
 * MCP sinks come from a separate vocabulary; a hit in the same
 * enclosing function as the A2A surface is the core boundary
 * confusion signal.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  A2A_AGENT_CARD,
  A2A_PART_SURFACE,
  A2A_PUSH_SURFACE,
  A2A_DISCOVERY_SURFACE,
  MCP_TOOL_SINKS,
  CONTENT_POLICY_IDENTIFIERS,
} from "./data/a2a-protocol-surfaces.js";

const AGENT_CARD_SET: ReadonlySet<string> = new Set(Object.keys(A2A_AGENT_CARD));
const PART_SET: ReadonlySet<string> = new Set(Object.keys(A2A_PART_SURFACE));
const PUSH_SET: ReadonlySet<string> = new Set(Object.keys(A2A_PUSH_SURFACE));
const DISCOVERY_SET: ReadonlySet<string> = new Set(
  Object.keys(A2A_DISCOVERY_SURFACE),
);
const MCP_SINK_SET: ReadonlySet<string> = new Set(Object.keys(MCP_TOOL_SINKS));
const POLICY_SET: ReadonlySet<string> = new Set(
  Object.keys(CONTENT_POLICY_IDENTIFIERS).map((k) => k.toLowerCase()),
);

// The a2a:// URI is a short string literal; keep it explicit here so the
// sniff is deterministic without regex.
const A2A_URI_PREFIX = "a2a://";

export type A2aSurfaceKind = "agent-card" | "part" | "push" | "discovery" | "uri";

export interface A2aSurfaceHit {
  kind: A2aSurfaceKind;
  token: string;
  location: Location;
}

export interface McpSinkHit {
  sinkName: string;
  location: Location;
}

export interface Q15Site {
  enclosingFunctionLocation: Location | null;
  a2aSurfaces: A2aSurfaceHit[];
  mcpSinks: McpSinkHit[];
  /** Policy identifier in enclosing scope, or null. */
  contentPolicyIdentifier: string | null;
}

export interface Q15Gathered {
  sites: Q15Site[];
  hasA2aSurface: boolean;
}

export function gatherQ15(context: AnalysisContext): Q15Gathered {
  const text = context.source_code;
  if (!text) return { sites: [], hasA2aSurface: false };

  const sf = ts.createSourceFile(
    "<concatenated-source>",
    text,
    ts.ScriptTarget.Latest,
    true,
  );

  if (!sourceHasA2aSurface(sf)) return { sites: [], hasA2aSurface: false };

  const sites: Q15Site[] = [];
  const scopes = collectFunctionScopes(sf);

  for (const scope of scopes) {
    const surfaces = collectA2aSurfaces(scope.node, sf);
    if (surfaces.length === 0) continue;
    const sinks = collectMcpSinks(scope.node, sf);
    if (sinks.length === 0) continue;
    const policy = findPolicyIdentifier(scope.node);
    sites.push({
      enclosingFunctionLocation: scope.location,
      a2aSurfaces: surfaces,
      mcpSinks: sinks,
      contentPolicyIdentifier: policy,
    });
  }

  return { sites, hasA2aSurface: true };
}

function sourceHasA2aSurface(sf: ts.SourceFile): boolean {
  let found = false;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n)) {
      const text = n.text;
      if (
        AGENT_CARD_SET.has(text) ||
        PART_SET.has(text) ||
        PUSH_SET.has(text) ||
        DISCOVERY_SET.has(text)
      ) {
        found = true;
        return;
      }
    } else if (ts.isPropertyAccessExpression(n)) {
      const name = n.name.text;
      if (
        AGENT_CARD_SET.has(name) ||
        PART_SET.has(name) ||
        PUSH_SET.has(name) ||
        DISCOVERY_SET.has(name)
      ) {
        found = true;
        return;
      }
    } else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      if (n.text.toLowerCase().startsWith(A2A_URI_PREFIX)) {
        found = true;
        return;
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(sf, visit);
  return found;
}

interface FunctionScope {
  node: ts.Node;
  location: Location | null;
}

function collectFunctionScopes(sf: ts.SourceFile): FunctionScope[] {
  const scopes: FunctionScope[] = [];
  ts.forEachChild(sf, function visit(node) {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node)
    ) {
      scopes.push({ node, location: sourceLocation(sf, node) });
    }
    ts.forEachChild(node, visit);
  });
  scopes.push({ node: sf, location: null });
  return scopes;
}

function collectA2aSurfaces(scope: ts.Node, sf: ts.SourceFile): A2aSurfaceHit[] {
  const hits: A2aSurfaceHit[] = [];
  function visit(n: ts.Node): void {
    if (ts.isPropertyAccessExpression(n)) {
      const name = n.name.text;
      const kind = classifyA2aToken(name);
      if (kind !== null) {
        hits.push({ kind, token: name, location: sourceLocation(sf, n) });
      }
    } else if (ts.isIdentifier(n)) {
      const kind = classifyA2aToken(n.text);
      if (kind !== null) {
        hits.push({ kind, token: n.text, location: sourceLocation(sf, n) });
      }
    } else if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n)) {
      if (n.text.toLowerCase().startsWith(A2A_URI_PREFIX)) {
        hits.push({ kind: "uri", token: n.text, location: sourceLocation(sf, n) });
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return hits;
}

function classifyA2aToken(token: string): A2aSurfaceKind | null {
  if (AGENT_CARD_SET.has(token)) return "agent-card";
  if (PART_SET.has(token)) return "part";
  if (PUSH_SET.has(token)) return "push";
  if (DISCOVERY_SET.has(token)) return "discovery";
  return null;
}

function collectMcpSinks(scope: ts.Node, sf: ts.SourceFile): McpSinkHit[] {
  const hits: McpSinkHit[] = [];
  function visit(n: ts.Node): void {
    if (ts.isCallExpression(n)) {
      const name = callName(n);
      if (name && MCP_SINK_SET.has(name)) {
        hits.push({ sinkName: name, location: sourceLocation(sf, n) });
      }
    }
    if (ts.isPropertyAccessExpression(n) && MCP_SINK_SET.has(n.name.text)) {
      // Property set: `tool.toolDescription = x` — mark the property access.
      hits.push({
        sinkName: n.name.text,
        location: sourceLocation(sf, n),
      });
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return hits;
}

function callName(call: ts.CallExpression): string | null {
  if (ts.isIdentifier(call.expression)) return call.expression.text;
  if (ts.isPropertyAccessExpression(call.expression)) return call.expression.name.text;
  return null;
}

function findPolicyIdentifier(scope: ts.Node): string | null {
  let found: string | null = null;
  function visit(n: ts.Node): void {
    if (found) return;
    if (ts.isIdentifier(n)) {
      const lower = n.text.toLowerCase();
      if (POLICY_SET.has(lower)) {
        found = n.text;
      }
    }
    ts.forEachChild(n, visit);
  }
  ts.forEachChild(scope, visit);
  return found;
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
