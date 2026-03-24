/**
 * Module Graph — cross-file symbol resolution for taint analysis.
 *
 * Given a map of { filePath → sourceCode }, builds:
 * 1. Export map: which symbols each file exports
 * 2. Import map: which symbols each file imports from other files
 * 3. Cross-file taint resolution: propagate taint across module boundaries
 *
 * Used by CodeAnalyzer to find vulnerabilities that span files:
 *   utils.ts exports getInput() → handler.ts imports and calls it → exec(getInput())
 *
 * Scope limits:
 * - Max 10 files per module graph
 * - Only relative imports resolved
 * - No transitive dependency resolution (only direct imports)
 * - Max call depth 3 for cross-file resolution
 */

import ts from "typescript";
import type { ASTTaintFlow, ASTTaintSource, ASTFlowStep } from "./taint-ast.js";
import { analyzeASTTaint } from "./taint-ast.js";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ModuleExport {
  /** Name of the exported symbol */
  name: string;
  /** Type: function, variable, class, default */
  kind: "function" | "variable" | "class" | "default" | "re-export";
  /** If function, parameter names */
  paramNames?: string[];
  /** Whether the function returns tainted data (from single-file taint analysis) */
  returnsTainted?: boolean;
  /** Taint info if the return value is tainted */
  taintSource?: ASTTaintSource;
  /** Source line of the export */
  line: number;
}

export interface ModuleImport {
  /** Source file path this import comes from */
  fromFile: string;
  /** Original import specifier (e.g., "./utils") */
  specifier: string;
  /** Local name in the importing file */
  localName: string;
  /** Original exported name in the source file */
  exportedName: string;
}

export interface ModuleInfo {
  filePath: string;
  /** Raw source code for this module (needed for cross-module re-analysis) */
  source: string;
  exports: ModuleExport[];
  imports: ModuleImport[];
  /** Single-file taint flows for this module */
  internalFlows: ASTTaintFlow[];
}

export interface CrossModuleFlow {
  /** The file where the vulnerability manifests (sink location) */
  sinkFile: string;
  /** The file where tainted data originates */
  sourceFile: string;
  /** The full taint flow with cross-module steps */
  flow: ASTTaintFlow;
  /** Human-readable module chain: "utils.ts:getInput() → handler.ts:process()" */
  moduleChain: string;
}

export interface ModuleGraph {
  modules: Map<string, ModuleInfo>;
  /** Cross-module taint flows discovered */
  crossModuleFlows: CrossModuleFlow[];
}

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_FILES = 10;

// ─── Module Graph Builder ───────────────────────────────────────────────────

/**
 * Build a module graph from a set of source files and discover cross-module taint flows.
 *
 * @param sourceFiles - Map of file path → source code content
 * @returns ModuleGraph with per-module info and cross-module taint flows
 */
export function buildModuleGraph(sourceFiles: Map<string, string>): ModuleGraph {
  const modules = new Map<string, ModuleInfo>();
  const entries = [...sourceFiles.entries()].slice(0, MAX_FILES);

  // Phase 1: Parse each file — extract exports, imports, and internal taint flows
  for (const [filePath, source] of entries) {
    const info = analyzeModule(filePath, source);
    modules.set(filePath, info);
  }

  // Phase 2: Resolve imports — connect import specifiers to actual file exports
  resolveImportLinks(modules);

  // Phase 3: Discover cross-module taint flows
  const crossModuleFlows = discoverCrossModuleFlows(modules);

  return { modules, crossModuleFlows };
}

// ─── Phase 1: Per-Module Analysis ───────────────────────────────────────────

function analyzeModule(filePath: string, source: string): ModuleInfo {
  const isPython = filePath.endsWith(".py");

  if (isPython) {
    return analyzePythonModule(filePath, source);
  }

  return analyzeJSModule(filePath, source);
}

function analyzeJSModule(filePath: string, source: string): ModuleInfo {
  const exports: ModuleExport[] = [];
  const imports: ModuleImport[] = [];

  let sourceFile: ts.SourceFile;
  try {
    sourceFile = ts.createSourceFile(
      filePath,
      source,
      ts.ScriptTarget.Latest,
      true,
      filePath.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );
  } catch {
    return { filePath, source, exports: [], imports: [], internalFlows: [] };
  }

  // Extract exports
  const visit = (node: ts.Node) => {
    // export function foo() {}
    if (ts.isFunctionDeclaration(node) && node.name && hasExportModifier(node)) {
      exports.push({
        name: node.name.text,
        kind: "function",
        paramNames: node.parameters.map((p) =>
          ts.isIdentifier(p.name) ? p.name.text : "_"
        ),
        line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
      });
    }

    // export const foo = ...
    if (ts.isVariableStatement(node) && hasExportModifier(node)) {
      for (const decl of node.declarationList.declarations) {
        if (ts.isIdentifier(decl.name)) {
          const init = decl.initializer;
          const isFunc = init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init));
          exports.push({
            name: decl.name.text,
            kind: isFunc ? "function" : "variable",
            paramNames: isFunc
              ? (init as ts.ArrowFunction | ts.FunctionExpression).parameters.map((p) =>
                  ts.isIdentifier(p.name) ? p.name.text : "_"
                )
              : undefined,
            line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          });
        }
      }
    }

    // export class Foo {}
    if (ts.isClassDeclaration(node) && node.name && hasExportModifier(node)) {
      exports.push({
        name: node.name.text,
        kind: "class",
        line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
      });
    }

    // export default ...
    if (ts.isExportAssignment(node)) {
      const name = ts.isIdentifier(node.expression) ? node.expression.text : "default";
      exports.push({
        name,
        kind: "default",
        line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
      });
    }

    // Named export list: export { foo, bar }
    if (ts.isExportDeclaration(node) && node.exportClause && ts.isNamedExports(node.exportClause)) {
      for (const spec of node.exportClause.elements) {
        exports.push({
          name: spec.name.text,
          kind: "re-export",
          line: sourceFile.getLineAndCharacterOfPosition(spec.getStart()).line + 1,
        });
      }
    }

    // Extract imports
    if (ts.isImportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const specifier = node.moduleSpecifier.text;
      if (!specifier.startsWith(".")) {
        ts.forEachChild(node, visit);
        return;
      }

      const importClause = node.importClause;
      if (!importClause) {
        ts.forEachChild(node, visit);
        return;
      }

      // Default import: import foo from "./bar"
      if (importClause.name) {
        imports.push({
          fromFile: "", // resolved in Phase 2
          specifier,
          localName: importClause.name.text,
          exportedName: "default",
        });
      }

      // Named imports: import { foo, bar as baz } from "./bar"
      if (importClause.namedBindings && ts.isNamedImports(importClause.namedBindings)) {
        for (const spec of importClause.namedBindings.elements) {
          imports.push({
            fromFile: "",
            specifier,
            localName: spec.name.text,
            exportedName: spec.propertyName?.text ?? spec.name.text,
          });
        }
      }

      // Namespace import: import * as foo from "./bar"
      if (importClause.namedBindings && ts.isNamespaceImport(importClause.namedBindings)) {
        imports.push({
          fromFile: "",
          specifier,
          localName: importClause.namedBindings.name.text,
          exportedName: "*",
        });
      }
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);

  // Run single-file taint analysis
  let internalFlows: ASTTaintFlow[] = [];
  try {
    internalFlows = analyzeASTTaint(source);
  } catch {
    // AST taint may fail on partial/malformed source
  }

  // Mark exports that return tainted data by analyzing function bodies directly
  for (const exp of exports) {
    if (exp.kind !== "function") continue;

    // First check: does any taint flow reference this function's return?
    for (const flow of internalFlows) {
      if (flow.path.some((step) =>
        step.type === "return_value" &&
        step.expression.includes(`${exp.name}()`)
      )) {
        exp.returnsTainted = true;
        exp.taintSource = flow.source;
        break;
      }
    }
    if (exp.returnsTainted) continue;

    // Second check: directly analyze the function's return statements for taint sources
    const funcNode = findFunctionNode(sourceFile, exp.name);
    if (funcNode) {
      const taintSource = checkFunctionReturnsTaint(sourceFile, funcNode);
      if (taintSource) {
        exp.returnsTainted = true;
        exp.taintSource = taintSource;
      }
    }
  }

  return { filePath, source, exports, imports, internalFlows };
}

/** Find a function declaration/expression node by name in the source file */
function findFunctionNode(sourceFile: ts.SourceFile, name: string): ts.Node | null {
  let found: ts.Node | null = null;
  const visit = (node: ts.Node) => {
    if (found) return;
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) {
      found = node;
      return;
    }
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      const init = node.initializer;
      if (init && (ts.isArrowFunction(init) || ts.isFunctionExpression(init))) {
        found = init;
        return;
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return found;
}

/** Known taint source property access chains */
const TAINT_SOURCE_CHAINS = [
  ["req", "body"], ["req", "params"], ["req", "query"], ["req", "headers"],
  ["request", "body"], ["request", "params"], ["request", "query"],
  ["request", "args"], ["request", "form"], ["request", "data"],
  ["process", "env"], ["process", "argv"],
  ["os", "environ"], ["sys", "argv"],
];

/** Check if a function's return statements contain taint sources */
function checkFunctionReturnsTaint(sourceFile: ts.SourceFile, funcNode: ts.Node): ASTTaintSource | null {
  const returns: ts.ReturnStatement[] = [];

  const collectReturns = (node: ts.Node) => {
    if (ts.isReturnStatement(node)) {
      returns.push(node);
    }
    // Don't descend into nested functions
    if (node !== funcNode && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node))) {
      return;
    }
    ts.forEachChild(node, collectReturns);
  };

  // Handle arrow functions with expression body
  if (ts.isArrowFunction(funcNode) && !ts.isBlock(funcNode.body)) {
    const taint = checkNodeForTaintSource(sourceFile, funcNode.body);
    if (taint) return taint;
  } else {
    collectReturns(funcNode);
    for (const ret of returns) {
      if (ret.expression) {
        const taint = checkNodeForTaintSource(sourceFile, ret.expression);
        if (taint) return taint;
      }
    }
  }

  return null;
}

/** Check if an AST node is or contains a taint source (property access chain) */
function checkNodeForTaintSource(sourceFile: ts.SourceFile, node: ts.Node): ASTTaintSource | null {
  // Property access: check against known chains
  if (ts.isPropertyAccessExpression(node)) {
    const chain = getPropertyChain(node);
    for (const src of TAINT_SOURCE_CHAINS) {
      if (chain.length >= src.length && src.every((part, i) => chain[i] === part)) {
        return {
          node,
          expression: chain.join("."),
          category: categorizeTaintSource(src),
          line: sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1,
          column: sourceFile.getLineAndCharacterOfPosition(node.getStart()).character,
        };
      }
    }
    // Check sub-expression
    const sub = checkNodeForTaintSource(sourceFile, node.expression);
    if (sub) return sub;
  }

  // Element access: check value
  if (ts.isElementAccessExpression(node)) {
    return checkNodeForTaintSource(sourceFile, node.expression);
  }

  // Recursively check children
  let result: ASTTaintSource | null = null;
  ts.forEachChild(node, (child) => {
    if (!result) result = checkNodeForTaintSource(sourceFile, child);
  });
  return result;
}

function getPropertyChain(node: ts.Node): string[] {
  const chain: string[] = [];
  let current: ts.Node = node;
  while (ts.isPropertyAccessExpression(current)) {
    chain.unshift(current.name.text);
    current = current.expression;
  }
  if (ts.isIdentifier(current)) {
    chain.unshift(current.text);
  }
  return chain;
}

function categorizeTaintSource(chain: string[]): string {
  const key = chain.join(".");
  if (key.includes("body") || key.includes("form") || key.includes("data")) return "http_body";
  if (key.includes("params") || key.includes("args")) return "http_params";
  if (key.includes("query")) return "http_query";
  if (key.includes("headers")) return "http_headers";
  if (key.includes("env") || key.includes("environ")) return "environment";
  if (key.includes("argv")) return "cli_args";
  return "unknown";
}

function analyzePythonModule(filePath: string, source: string): ModuleInfo {
  const exports: ModuleExport[] = [];
  const imports: ModuleImport[] = [];

  // Python exports: module-level def/class/variable (no explicit export keyword)
  // Heuristic: all module-level functions and classes are "exported"

  // Functions: def foo(x, y):
  const funcRe = /^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)/gm;
  let m: RegExpExecArray | null;
  while ((m = funcRe.exec(source))) {
    if (m[1].startsWith("_") && !m[1].startsWith("__")) continue; // skip private
    const paramStr = m[2];
    const paramNames = paramStr
      .split(",")
      .map((p) => p.trim().split(":")[0].split("=")[0].trim())
      .filter((p) => p && p !== "self" && p !== "cls");
    const line = source.slice(0, m.index).split("\n").length;
    exports.push({ name: m[1], kind: "function", paramNames, line });
  }

  // Classes: class Foo:
  const classRe = /^class\s+(\w+)/gm;
  while ((m = classRe.exec(source))) {
    if (m[1].startsWith("_")) continue;
    const line = source.slice(0, m.index).split("\n").length;
    exports.push({ name: m[1], kind: "class", line });
  }

  // Module-level variables: FOO = ... or foo = ... (non-indented)
  const varRe = /^([A-Za-z]\w*)\s*=/gm;
  while ((m = varRe.exec(source))) {
    const name = m[1];
    if (exports.some((e) => e.name === name)) continue; // already captured as func/class
    if (name.startsWith("_")) continue;
    const line = source.slice(0, m.index).split("\n").length;
    exports.push({ name, kind: "variable", line });
  }

  // Python relative imports: from .utils import foo, bar
  const importRe = /from\s+(\.+\w*(?:\.\w+)*)\s+import\s+(.+)/g;
  while ((m = importRe.exec(source))) {
    const specifier = m[1];
    const importList = m[2].split(",").map((s) => s.trim().split(" as "));
    for (const parts of importList) {
      const exportedName = parts[0].trim();
      const localName = (parts[1] || parts[0]).trim();
      if (exportedName && localName) {
        imports.push({
          fromFile: "",
          specifier,
          localName,
          exportedName,
        });
      }
    }
  }

  // No AST taint for Python here — that runs via the Python taint engine separately
  return { filePath, source, exports, imports, internalFlows: [] };
}

function hasExportModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  const mods = ts.getModifiers(node);
  return mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
}

// ─── Phase 2: Resolve Import Links ─────────────────────────────────────────

function resolveImportLinks(modules: Map<string, ModuleInfo>): void {
  const fileMap = new Map<string, string>(); // normalized base → actual filePath

  // Build lookup: "src/utils" → "src/utils.ts"
  for (const filePath of modules.keys()) {
    fileMap.set(filePath, filePath);
    // Also register without extension
    const noExt = filePath.replace(/\.(ts|tsx|js|jsx|mjs|cjs|py)$/, "");
    fileMap.set(noExt, filePath);
    // Register index file under directory name
    if (filePath.endsWith("/index.ts") || filePath.endsWith("/index.js") || filePath.endsWith("/__init__.py")) {
      const dir = filePath.slice(0, filePath.lastIndexOf("/"));
      fileMap.set(dir, filePath);
    }
  }

  for (const [filePath, moduleInfo] of modules) {
    for (const imp of moduleInfo.imports) {
      // Resolve specifier relative to the importing file's directory
      const dir = filePath.includes("/") ? filePath.slice(0, filePath.lastIndexOf("/")) : "";
      const resolved = resolveRelativePath(dir, imp.specifier);
      if (!resolved) continue;

      // Try to find the actual file
      const actual =
        fileMap.get(resolved) ||
        fileMap.get(resolved.replace(/\./g, "/")) || // Python dot notation
        null;

      if (actual) {
        imp.fromFile = actual;
      }
    }
  }
}

function resolveRelativePath(dir: string, specifier: string): string | null {
  // Python relative imports: .utils → utils, ..lib → ../lib
  if (/^\.+\w/.test(specifier)) {
    const dotsMatch = specifier.match(/^(\.+)/);
    if (!dotsMatch) return null;
    const dots = dotsMatch[1].length;
    const modulePart = specifier.slice(dots).replace(/\./g, "/");

    let base = dir;
    for (let i = 1; i < dots; i++) {
      const last = base.lastIndexOf("/");
      base = last === -1 ? "" : base.slice(0, last);
    }

    return base ? `${base}/${modulePart}` : modulePart;
  }

  // JS relative imports: ./utils, ../lib/db
  if (specifier.startsWith(".")) {
    const parts = (dir ? `${dir}/${specifier}` : specifier).split("/");
    const resolved: string[] = [];
    for (const part of parts) {
      if (part === "." || part === "") continue;
      if (part === "..") {
        if (resolved.length === 0) return null;
        resolved.pop();
      } else {
        resolved.push(part);
      }
    }
    return resolved.join("/") || null;
  }

  return null;
}

// ─── Phase 3: Cross-Module Taint Discovery ──────────────────────────────────

/**
 * Discover cross-module taint flows using two strategies:
 *
 * Strategy A: "Tainted Return" — An exported function in module A returns tainted data.
 *   Module B imports and calls it, passing the result to a sink.
 *   We detect this by re-analyzing module B's source with the imported function
 *   treated as a taint source.
 *
 * Strategy B: "Tainted Passthrough" — Module B calls an imported function with tainted args,
 *   and that function in module A passes the arg to a sink.
 *   We detect this from existing per-module taint flows.
 */
function discoverCrossModuleFlows(modules: Map<string, ModuleInfo>): CrossModuleFlow[] {
  const crossFlows: CrossModuleFlow[] = [];

  // First, identify which exported functions return tainted data
  const taintedExports = new Map<string, { filePath: string; exportName: string; taintSource: ASTTaintSource }>();

  for (const [filePath, moduleInfo] of modules) {
    for (const flow of moduleInfo.internalFlows) {
      // A flow where the source is tainted and appears in a return/function pattern
      // means the enclosing function "returns" tainted data
      for (const exp of moduleInfo.exports) {
        if (exp.kind !== "function") continue;

        // Check if this flow is inside the exported function:
        // - Source or path mentions the function's parameters
        // - The flow ends with data being returned or used as function return
        const flowInvolvesExport =
          flow.path.some((step) =>
            step.expression.includes(`${exp.name}()`) ||
            step.expression.includes(`returns tainted`)
          ) ||
          // Also: if the exported function has a source (req.body etc.) inside it
          (exp.returnsTainted && exp.taintSource);

        if (flowInvolvesExport && !taintedExports.has(`${filePath}:${exp.name}`)) {
          taintedExports.set(`${filePath}:${exp.name}`, {
            filePath,
            exportName: exp.name,
            taintSource: flow.source,
          });
        }
      }
    }

    // Also check via return statement analysis (functions that directly return tainted values)
    for (const exp of moduleInfo.exports) {
      if (exp.returnsTainted && exp.taintSource) {
        taintedExports.set(`${filePath}:${exp.name}`, {
          filePath,
          exportName: exp.name,
          taintSource: exp.taintSource,
        });
      }
    }
  }

  // Strategy A: Re-analyze importing files with cross-module taint knowledge
  for (const [filePath, moduleInfo] of modules) {
    for (const imp of moduleInfo.imports) {
      if (!imp.fromFile) continue;

      const taintedKey = `${imp.fromFile}:${imp.exportedName}`;
      const taintedExport = taintedExports.get(taintedKey);
      if (!taintedExport) continue;

      // This file imports a function that returns tainted data.
      // Synthesize a taint flow: treat calls to the imported function as taint sources.
      // Re-analyze the importing file's source with the imported function as a known source.
      const sourceModule = modules.get(imp.fromFile);
      if (!sourceModule) continue;

      const exportedSymbol = sourceModule.exports.find(
        (e) => e.name === imp.exportedName
      );

      // Check importing file's flows: look for sinks where the imported function
      // call feeds into a dangerous sink
      const importingSource = getSourceForFile(modules, filePath);
      if (!importingSource) continue;

      // Find calls to the imported function and track their usage to sinks
      // using simple pattern: localName() appears in sink arguments
      const callPattern = new RegExp(
        `(?:const|let|var)\\s+(\\w+)\\s*=\\s*(?:await\\s+)?${escapeRegex(imp.localName)}\\s*\\(`,
        "g"
      );

      let callMatch: RegExpExecArray | null;
      while ((callMatch = callPattern.exec(importingSource))) {
        const resultVar = callMatch[1];
        const assignLine = importingSource.slice(0, callMatch.index).split("\n").length;

        // Scan the importing source for known sink calls that use resultVar
        const sinkCallRe = new RegExp(`(\\w+)\\s*\\(\\s*${escapeRegex(resultVar)}\\b`, "g");
        let sinkMatch: RegExpExecArray | null;
        while ((sinkMatch = sinkCallRe.exec(importingSource))) {
          const sinkFn = sinkMatch[1];
          const category = guessSinkCategory(sinkFn);
          if (category === "unknown") continue;

          const sinkLine = importingSource.slice(0, sinkMatch.index).split("\n").length;
          const moduleChain = `${basename(imp.fromFile)}:${imp.exportedName}() → ${basename(filePath)}:${sinkFn}()`;

          crossFlows.push({
            sinkFile: filePath,
            sourceFile: imp.fromFile,
            flow: {
              source: taintedExport.taintSource,
              sink: {
                node: null as unknown as ts.Node,
                expression: `${sinkFn}(${resultVar})`,
                category,
                line: sinkLine,
                column: 0,
                dangerous_args: [0],
              },
              path: [
                {
                  type: "return_value",
                  expression: `${basename(imp.fromFile)}:${imp.exportedName}() returns tainted ${taintedExport.taintSource.category}`,
                  line: exportedSymbol?.line ?? 0,
                },
                {
                  type: "assignment",
                  expression: `${resultVar} = ${imp.localName}()`,
                  line: assignLine,
                },
              ],
              sanitized: false,
              confidence: 0.88,
            },
            moduleChain,
          });
        }
      }

      // Handle direct usage: exec(importedFunc())
      const directCallPattern = new RegExp(
        `(\\w+)\\s*\\(\\s*(?:await\\s+)?${escapeRegex(imp.localName)}\\s*\\(`,
        "g"
      );
      let directMatch: RegExpExecArray | null;
      while ((directMatch = directCallPattern.exec(importingSource))) {
        const sinkCandidate = directMatch[1];
        const category = guessSinkCategory(sinkCandidate);
        if (category === "unknown") continue;

        const line = importingSource.slice(0, directMatch.index).split("\n").length;
        const moduleChain = `${basename(imp.fromFile)}:${imp.exportedName}() → ${basename(filePath)}:${sinkCandidate}()`;

        crossFlows.push({
          sinkFile: filePath,
          sourceFile: imp.fromFile,
          flow: {
            source: taintedExport.taintSource,
            sink: {
              node: null as unknown as ts.Node,
              expression: `${sinkCandidate}(${imp.localName}())`,
              category,
              line,
              column: 0,
              dangerous_args: [0],
            },
            path: [
              {
                type: "return_value",
                expression: `${basename(imp.fromFile)}:${imp.exportedName}() returns tainted ${taintedExport.taintSource.category}`,
                line: exportedSymbol?.line ?? 0,
              },
              {
                type: "parameter_binding",
                expression: `${imp.localName}() result passed directly to ${sinkCandidate}()`,
                line,
              },
            ],
            sanitized: false,
            confidence: 0.85,
          },
          moduleChain,
        });
      }
    }
  }

  // Strategy B: Cross-flow from existing per-module flows that reference imported symbols
  for (const [filePath, moduleInfo] of modules) {
    for (const imp of moduleInfo.imports) {
      if (!imp.fromFile) continue;

      const sourceModule = modules.get(imp.fromFile);
      if (!sourceModule) continue;

      for (const flow of moduleInfo.internalFlows) {
        const usesImport =
          flow.source.expression.includes(imp.localName) ||
          flow.path.some((step) => step.expression.includes(imp.localName));

        if (!usesImport) continue;

        // Check if the source module has related taint flows
        const hasRelatedSourceFlows = sourceModule.internalFlows.some((sf) =>
          sf.path.some((step) => step.expression.includes(imp.exportedName)) ||
          sf.source.expression.includes(imp.exportedName)
        );

        if (hasRelatedSourceFlows) {
          const moduleChain = `${basename(imp.fromFile)}:${imp.exportedName}() → ${basename(filePath)}`;
          const crossModuleStep: ASTFlowStep = {
            type: "parameter_binding",
            expression: `import ${imp.localName} from "${imp.specifier}" → ${basename(imp.fromFile)}:${imp.exportedName}`,
            line: 0,
          };

          crossFlows.push({
            sinkFile: filePath,
            sourceFile: imp.fromFile,
            flow: {
              ...flow,
              path: [crossModuleStep, ...flow.path],
              confidence: Math.min(flow.confidence * 1.05, 0.99),
            },
            moduleChain,
          });
        }
      }
    }
  }

  return crossFlows;
}

function getSourceForFile(modules: Map<string, ModuleInfo>, filePath: string): string | null {
  return modules.get(filePath)?.source ?? null;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Guess a sink category from a function name */
function guessSinkCategory(fnName: string): string {
  const categories: Record<string, string> = {
    exec: "command_execution", execSync: "command_execution",
    spawn: "command_execution", spawnSync: "command_execution",
    system: "command_execution", popen: "command_execution",
    eval: "code_eval", Function: "code_eval",
    query: "sql_injection", execute: "sql_injection", raw: "sql_injection",
    fetch: "ssrf", get: "ssrf", post: "ssrf", request: "ssrf",
    readFile: "path_traversal", writeFile: "path_traversal",
    loads: "deserialization", load: "deserialization",
  };
  return categories[fnName] || "unknown";
}

function basename(filePath: string): string {
  const last = filePath.lastIndexOf("/");
  return last === -1 ? filePath : filePath.slice(last + 1);
}

// ─── Public Helpers ─────────────────────────────────────────────────────────

/**
 * Check if a source_files map has enough data for cross-module analysis.
 */
export function hasMultiFileContext(sourceFiles: Map<string, string> | undefined | null): boolean {
  return !!sourceFiles && sourceFiles.size > 1;
}
