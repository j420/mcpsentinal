/**
 * L4 evidence gathering — structural, AST-only.
 *
 * Walks the TypeScript/JavaScript AST to find object-literal subtrees
 * that match the MCP config shape (have a `mcpServers` key or sit
 * under a known MCP-config filename write), then inspects their
 * `command`, `args`, and `env` children for each of the L4 primitives
 * defined in the CHARTER:
 *
 *   1. shell-interpreter-command — command starts with bash/sh/zsh/...
 *   2. fetch-and-execute-in-args — args carry curl|wget…|sh
 *   3. api-base-env-redirect     — env overrides ANTHROPIC_API_URL etc.
 *   4. sensitive-env-in-args     — args reference ${API_KEY} / ${TOKEN}
 *
 * Zero regex. All vocabulary lives in `data/mcp-config-markers.ts`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  API_BASE_ENV_NAMES,
  FETCH_AND_EXECUTE_TOKENS,
  MCP_CONFIG_CONTEXT_MARKERS,
  MCP_CONFIG_FILENAMES,
  SENSITIVE_ENV_SUBSTRINGS,
  SHELL_EVAL_FLAGS,
  SHELL_INTERPRETERS,
} from "./data/mcp-config-markers.js";

const CONTEXT_MARKER_SET: ReadonlySet<string> = new Set(Object.keys(MCP_CONFIG_CONTEXT_MARKERS));
const FILENAME_SET: ReadonlySet<string> = new Set(Object.keys(MCP_CONFIG_FILENAMES));
const SHELL_SET: ReadonlySet<string> = new Set(Object.keys(SHELL_INTERPRETERS));
const EVAL_FLAG_SET: ReadonlySet<string> = new Set(Object.keys(SHELL_EVAL_FLAGS));
const API_BASE_SET: ReadonlySet<string> = new Set(Object.keys(API_BASE_ENV_NAMES));
const FETCH_EXEC_TOKENS: ReadonlySet<string> = new Set(Object.keys(FETCH_AND_EXECUTE_TOKENS));
const SENSITIVE_ENV_TOKENS: ReadonlySet<string> = new Set(
  Object.keys(SENSITIVE_ENV_SUBSTRINGS),
);

// ─── Public types ──────────────────────────────────────────────────────────

export type L4PrimitiveKind =
  | "shell-interpreter-command"
  | "fetch-and-execute-in-args"
  | "api-base-env-redirect"
  | "sensitive-env-in-args";

export interface L4Primitive {
  kind: L4PrimitiveKind;
  /** Structured Location for the specific offending node (command/args/env child). */
  location: Location;
  /** Short textual observation (≤200 chars) — what a reviewer sees. */
  observed: string;
  /** Structured tag for per-primitive rationale. */
  detail: string;
}

export interface L4ConfigContext {
  /** Location of the outer config object literal. */
  literalLocation: Location;
  /** Whether we also saw a writeFileSync targeting an MCP config filename. */
  writesToConfigFile: boolean;
  /** Best-effort config-file Location if writesToConfigFile is true. */
  targetConfigFile: Location | null;
  /** All primitives observed under this literal. */
  primitives: L4Primitive[];
}

export interface L4GatherResult {
  file: string;
  isTestFile: boolean;
  contexts: L4ConfigContext[];
}

// ─── Entry point ───────────────────────────────────────────────────────────

const SYNTHETIC_FILE = "<source>";

export function gatherL4(context: AnalysisContext): L4GatherResult {
  const src = context.source_code;
  if (!src) return { file: SYNTHETIC_FILE, isTestFile: false, contexts: [] };

  const file = firstFile(context.source_files) ?? SYNTHETIC_FILE;
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
  const isTestFile = detectTestFileShape(sf);

  // Pass 1: collect all mcpServers-keyed object literals.
  const candidateLiterals: ts.ObjectLiteralExpression[] = [];
  const writePaths = new Set<string>();

  const visit = (node: ts.Node): void => {
    if (ts.isObjectLiteralExpression(node) && hasContextMarker(node)) {
      candidateLiterals.push(node);
    }
    // Collect writeFileSync targets. We accept either a string literal or a
    // template literal whose fragments include an MCP-config filename suffix.
    if (ts.isCallExpression(node) && isConfigWrite(node)) {
      const pathText = getFirstArgText(node, sf);
      if (pathText !== null) writePaths.add(pathText);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(sf, visit);

  const contexts: L4ConfigContext[] = [];
  for (const lit of candidateLiterals) {
    const literalLocation = locOf(sf, file, lit);
    const primitives = collectPrimitivesForLiteral(lit, sf, file);
    if (primitives.length === 0) continue;

    // Does a config-write exist anywhere in the same file? The match is
    // per-file rather than per-literal because static analysis cannot
    // always prove the literal IS the payload being written.
    const targetConfigFile = firstMatchingWriteConfig(writePaths);
    contexts.push({
      literalLocation,
      writesToConfigFile: targetConfigFile !== null,
      targetConfigFile,
      primitives,
    });
  }

  return { file, isTestFile, contexts };
}

// ─── AST helpers ───────────────────────────────────────────────────────────

function firstFile(source_files: AnalysisContext["source_files"]): string | null {
  if (!source_files || source_files.size === 0) return null;
  return Array.from(source_files.keys())[0];
}

function detectTestFileShape(sf: ts.SourceFile): boolean {
  const name = sf.fileName.toLowerCase();
  if (name.endsWith(".test.ts") || name.endsWith(".test.js")) return true;
  if (name.endsWith(".spec.ts") || name.endsWith(".spec.js")) return true;
  if (name.includes("__tests__") || name.includes("__fixtures__/test-")) return true;
  // Structural: top-level describe() / it() call AND an import from vitest / jest.
  let hasTestImport = false;
  let hasTestCall = false;
  for (const stmt of sf.statements) {
    if (ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier)) {
      const s = stmt.moduleSpecifier.text;
      if (s === "vitest" || s === "jest" || s === "mocha") hasTestImport = true;
    }
    if (ts.isExpressionStatement(stmt) && ts.isCallExpression(stmt.expression)) {
      const callee = stmt.expression.expression;
      if (ts.isIdentifier(callee)) {
        if (callee.text === "describe" || callee.text === "it" || callee.text === "test") {
          hasTestCall = true;
        }
      }
    }
  }
  return hasTestImport && hasTestCall;
}

function hasContextMarker(node: ts.ObjectLiteralExpression): boolean {
  for (const prop of node.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const keyName = propertyKeyName(prop);
    if (keyName !== null && CONTEXT_MARKER_SET.has(keyName)) return true;
  }
  return false;
}

function propertyKeyName(prop: ts.PropertyAssignment): string | null {
  if (ts.isIdentifier(prop.name)) return prop.name.text;
  if (ts.isStringLiteral(prop.name)) return prop.name.text;
  return null;
}

function locOf(sf: ts.SourceFile, file: string, node: ts.Node): Location {
  const start = node.getStart(sf);
  const { line, character } = sf.getLineAndCharacterOfPosition(start);
  return { kind: "source", file, line: line + 1, col: character + 1 };
}

function isConfigWrite(node: ts.CallExpression): boolean {
  const callee = node.expression;
  let name: string | null = null;
  if (ts.isIdentifier(callee)) name = callee.text;
  else if (ts.isPropertyAccessExpression(callee)) name = callee.name.text;
  if (name === null) return false;
  return name === "writeFileSync" || name === "writeFile" ||
         name === "appendFile" || name === "appendFileSync" ||
         name === "outputFile" || name === "outputFileSync";
}

function getFirstArgText(node: ts.CallExpression, sf: ts.SourceFile): string | null {
  if (node.arguments.length === 0) return null;
  const arg = node.arguments[0];
  if (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)) return arg.text;
  // Template literal — concatenate the literal head + tail without substitutions.
  if (ts.isTemplateExpression(arg)) {
    const fragments: string[] = [arg.head.text];
    for (const span of arg.templateSpans) fragments.push(span.literal.text);
    return fragments.join("");
  }
  return arg.getText(sf);
}

function firstMatchingWriteConfig(paths: ReadonlySet<string>): Location | null {
  for (const path of paths) {
    const norm = path.toLowerCase();
    for (const suffix of FILENAME_SET) {
      if (norm.includes(suffix)) {
        return { kind: "config", file: path, json_pointer: "/" };
      }
    }
  }
  return null;
}

// ─── Primitive collection (per config literal) ────────────────────────────

function collectPrimitivesForLiteral(
  lit: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
): L4Primitive[] {
  const out: L4Primitive[] = [];
  // Walk into each `mcpServers: { <name>: { command, args, env } }` subtree.
  for (const prop of lit.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === null) continue;
    if (!CONTEXT_MARKER_SET.has(key)) continue;
    // Inspect the subtree recursively — multiple servers may be declared.
    inspectServersObject(prop.initializer, sf, file, out);
  }
  return out;
}

function inspectServersObject(
  node: ts.Expression,
  sf: ts.SourceFile,
  file: string,
  out: L4Primitive[],
): void {
  if (!ts.isObjectLiteralExpression(node)) return;
  for (const prop of node.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    // Each entry under mcpServers is a single server definition.
    if (ts.isObjectLiteralExpression(prop.initializer)) {
      inspectServerEntry(prop.initializer, sf, file, out);
    }
  }
}

function inspectServerEntry(
  entry: ts.ObjectLiteralExpression,
  sf: ts.SourceFile,
  file: string,
  out: L4Primitive[],
): void {
  let commandText: string | null = null;
  let commandLoc: Location | null = null;
  const argsStrings: { text: string; loc: Location }[] = [];
  const envEntries: { name: string; value: string; loc: Location }[] = [];

  for (const prop of entry.properties) {
    if (!ts.isPropertyAssignment(prop)) continue;
    const key = propertyKeyName(prop);
    if (key === null) continue;
    if (key === "command") {
      if (ts.isStringLiteral(prop.initializer) || ts.isNoSubstitutionTemplateLiteral(prop.initializer)) {
        commandText = prop.initializer.text;
        commandLoc = locOf(sf, file, prop.initializer);
      }
    } else if (key === "args") {
      if (ts.isArrayLiteralExpression(prop.initializer)) {
        for (const el of prop.initializer.elements) {
          if (ts.isStringLiteral(el) || ts.isNoSubstitutionTemplateLiteral(el)) {
            argsStrings.push({ text: el.text, loc: locOf(sf, file, el) });
          } else if (ts.isTemplateExpression(el)) {
            const merged = collapseTemplate(el);
            argsStrings.push({ text: merged, loc: locOf(sf, file, el) });
          }
        }
      }
    } else if (key === "env") {
      if (ts.isObjectLiteralExpression(prop.initializer)) {
        for (const envProp of prop.initializer.properties) {
          if (!ts.isPropertyAssignment(envProp)) continue;
          const envKey = propertyKeyName(envProp);
          if (envKey === null) continue;
          const envVal = literalOrTemplateText(envProp.initializer);
          envEntries.push({ name: envKey, value: envVal, loc: locOf(sf, file, envProp) });
        }
      }
    }
  }

  // Primitive 1: shell-interpreter-command.
  if (commandText !== null && commandLoc !== null) {
    const base = commandText.split("/").pop() ?? commandText;
    if (SHELL_SET.has(base.toLowerCase())) {
      out.push({
        kind: "shell-interpreter-command",
        location: commandLoc,
        observed: `command: "${commandText}"`,
        detail:
          `MCP config's command field invokes shell interpreter "${base}". ` +
          `Client spawns with the full args list — a shell interpreter turns the ` +
          `subsequent -c / -e argument into an arbitrary shell string (CVE-2025-59536).`,
      });
    }
  }

  // Primitive 1b: shell eval flag in args alongside any command.
  if (commandText !== null && commandLoc !== null) {
    const base = (commandText.split("/").pop() ?? commandText).toLowerCase();
    if (SHELL_SET.has(base)) {
      const evalFlag = argsStrings.find((a) => EVAL_FLAG_SET.has(a.text));
      if (evalFlag) {
        out.push({
          kind: "shell-interpreter-command",
          location: evalFlag.loc,
          observed: `args: [… "${evalFlag.text}" …]`,
          detail:
            `Shell eval flag "${evalFlag.text}" following a shell interpreter ` +
            `command is the direct exec primitive (CVE-2025-59536).`,
        });
      }
    }
  }

  // Primitive 2: fetch-and-execute tokens in any args string.
  for (const arg of argsStrings) {
    for (const token of FETCH_EXEC_TOKENS) {
      if (arg.text.includes(token)) {
        out.push({
          kind: "fetch-and-execute-in-args",
          location: arg.loc,
          observed: `args entry: "${arg.text.slice(0, 160)}"`,
          detail:
            `Args entry carries a fetch-and-execute payload token (${token.trim()}) — ` +
            `the remote-fetch variant of the CVE-2025-59536 primitive.`,
        });
        break;
      }
    }
  }

  // Primitive 2b: sensitive-env-in-args.
  for (const arg of argsStrings) {
    for (const token of SENSITIVE_ENV_TOKENS) {
      if (arg.text.includes(token)) {
        out.push({
          kind: "sensitive-env-in-args",
          location: arg.loc,
          observed: `args entry: "${arg.text.slice(0, 160)}"`,
          detail:
            `Args entry references sensitive environment variable "${token}" — the ` +
            `server process reads its own argv and exfiltrates the credential ` +
            `(CVE-2026-21852 exfiltration primitive).`,
        });
        break;
      }
    }
  }

  // Primitive 3: api-base-env-redirect.
  for (const e of envEntries) {
    if (API_BASE_SET.has(e.name)) {
      out.push({
        kind: "api-base-env-redirect",
        location: e.loc,
        observed: `env.${e.name} = "${e.value.slice(0, 120)}"`,
        detail:
          `env block redirects ${e.name} — the server's outbound AI traffic is ` +
          `proxied through an attacker-controlled endpoint (CVE-2026-21852 API-key ` +
          `exfiltration primitive). No shell invocation required.`,
      });
    }
  }

  // Primitive 3b: sensitive env entries in env block (credential leak to process env).
  for (const e of envEntries) {
    for (const token of SENSITIVE_ENV_TOKENS) {
      if (e.name.includes(token)) {
        out.push({
          kind: "sensitive-env-in-args",
          location: e.loc,
          observed: `env.${e.name}`,
          detail:
            `env block carries sensitive key "${e.name}" — the credential is shipped ` +
            `to the server process environment and, on CVE-2026-21852-class hosts, ` +
            `visible to its outbound traffic.`,
        });
        break;
      }
    }
  }
}

function collapseTemplate(node: ts.TemplateExpression): string {
  const parts: string[] = [node.head.text];
  for (const span of node.templateSpans) {
    parts.push("${...}");
    parts.push(span.literal.text);
  }
  return parts.join("");
}

function literalOrTemplateText(node: ts.Expression): string {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isTemplateExpression(node)) return collapseTemplate(node);
  return node.getText();
}
