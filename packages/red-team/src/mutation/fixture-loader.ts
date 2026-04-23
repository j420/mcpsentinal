/**
 * Fixture loading for the mutation auditor.
 *
 * Rule fixtures come in two shapes in this codebase:
 *
 * 1. **Raw-source fixture**: the .ts file itself IS the vulnerable code. The
 *    rule sees the file contents as `AnalysisContext.source_code`. Examples:
 *    K1 true-positive-01-express-console.ts is just an Express app using
 *    console.log.
 *
 * 2. **Context fixture**: the .ts file exports either
 *      - `function buildContext(): AnalysisContext`, or
 *      - `const fixture: AnalysisContext` / `const fixture = { ... }`
 *    The rule sees the returned object — the fixture source text is never
 *    seen directly by the rule. Examples: A1 true-positive-01-role-override.ts
 *    returns a context with a malicious tool description.
 *
 * The mutation runner applies the 8 AST-level mutations to the fixture's
 * SOURCE TEXT. For raw-source fixtures the mutated text is fed into
 * `source_code` directly; for context fixtures the mutated TS is
 * transpiled-in-process via `typescript.transpileModule` and evaluated in a
 * fresh `vm` context, producing a mutated `AnalysisContext`.
 *
 * A context-fixture mutation that evaluates to the same runtime context as
 * the unmutated fixture (because the mutation only touched syntax that gets
 * evaluated away, e.g. split-string-literal concatenation) is not flagged
 * here — the runner relies on before/after finding-count comparison, and if
 * the mutation produced no SEMANTIC change the rule's finding count will
 * match exactly. That's a "survived" outcome, which is an honest signal.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, dirname, basename } from "node:path";
import { createRequire } from "node:module";
import vm from "node:vm";
import ts from "typescript";
import type { AnalysisContext } from "@mcp-sentinel/analyzer";

const require_ = createRequire(import.meta.url);

export type FixtureKind =
  | "raw-source"
  | "context-build"
  | "context-const"
  | "tool-const"
  | "source-string-const"
  | "unknown";

export interface LoadedFixture {
  absPath: string;
  filename: string;
  text: string;
  kind: FixtureKind;
  /** Built the AnalysisContext from the ORIGINAL (unmutated) fixture source. */
  buildContext: () => AnalysisContext;
}

/**
 * Classify a fixture by scanning its top-level export declarations with the
 * TypeScript parser. We do NOT use string matching here — the raw-source
 * fixtures frequently contain the word "buildContext" in comments, and we
 * need a structural answer.
 */
export function classifyFixture(text: string, filename = "fixture.ts"): FixtureKind {
  const sf = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, /*setParentNodes*/ true, ts.ScriptKind.TS);

  let hasBuildContext = false;
  let fixtureConstKind: "tool" | "context" | "unknown-object" | null = null;
  let hasSourceStringConst = false;
  let hasAnyExport = false;

  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt)) {
      const isExport = stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
      if (isExport && stmt.name?.text === "buildContext") {
        hasBuildContext = true;
      }
      if (isExport) hasAnyExport = true;
    } else if (ts.isVariableStatement(stmt)) {
      const isExport = stmt.modifiers?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword) ?? false;
      if (isExport) {
        hasAnyExport = true;
        for (const decl of stmt.declarationList.declarations) {
          if (!ts.isIdentifier(decl.name)) continue;
          const name = decl.name.text;
          if (name === "fixture") {
            const init = decl.initializer;
            if (init && ts.isObjectLiteralExpression(init)) {
              fixtureConstKind = classifyFixtureObject(init);
            } else {
              fixtureConstKind = "unknown-object";
            }
          } else if (name === "source") {
            // `export const source = \`...\``  → treat as raw-source fed through
            // the rule via source_code.
            const init = decl.initializer;
            if (
              init &&
              (ts.isNoSubstitutionTemplateLiteral(init) ||
                ts.isTemplateExpression(init) ||
                ts.isStringLiteral(init) ||
                ts.isCallExpression(init))
            ) {
              hasSourceStringConst = true;
            }
          }
        }
      }
    } else if (
      ts.isExportDeclaration(stmt) ||
      ts.isExportAssignment(stmt) ||
      ts.isClassDeclaration(stmt) ||
      ts.isInterfaceDeclaration(stmt)
    ) {
      const mods = ts.canHaveModifiers(stmt) ? ts.getModifiers(stmt) : undefined;
      if (mods?.some((m) => m.kind === ts.SyntaxKind.ExportKeyword)) hasAnyExport = true;
    }
  }

  if (hasBuildContext) return "context-build";
  if (fixtureConstKind === "context") return "context-const";
  if (fixtureConstKind === "tool") return "tool-const";
  if (hasSourceStringConst) return "source-string-const";
  if (!hasAnyExport) return "raw-source";
  return "unknown";
}

/**
 * Look at the property names of an object literal assigned to `fixture` and
 * decide whether it's an `AnalysisContext`-shaped object (has `server` +
 * `tools`) or a tool-shaped object (has `name` + `description` + optionally
 * `input_schema`). This is load-bearing — getting it wrong makes the mutation
 * runner feed the rule the wrong shape of data.
 */
function classifyFixtureObject(obj: ts.ObjectLiteralExpression): "tool" | "context" | "unknown-object" {
  const names = new Set<string>();
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
      names.add(prop.name.text);
    } else if (ts.isShorthandPropertyAssignment(prop)) {
      names.add(prop.name.text);
    }
  }
  if (names.has("server") && names.has("tools")) return "context";
  if (names.has("name") && names.has("description")) return "tool";
  return "unknown-object";
}

/**
 * Transpile TS → CJS in-process and evaluate the emitted JS in a Node-flavoured
 * `vm` context so we can extract the exports. We go through CJS (not ESM) to
 * avoid the top-level-await / dynamic-import dance that would otherwise be
 * required to run mutated fixtures from the runner.
 *
 * Why vm and not `Function` / eval: vm gives us a controlled `require` and
 * `module` surface that matches Node's module loading, so fixtures that
 * `import type` from `../../../../engine.js` or `import { ... } from "..."`
 * resolve through the normal resolver. Type-only imports compile to nothing
 * in the emit, so there's almost never a runtime-import to resolve in a
 * fixture; the closed runtime surface of the fixtures is extremely small in
 * practice.
 */
function evaluateModule(source: string, absPath: string): Record<string, unknown> {
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      skipLibCheck: true,
      allowJs: true,
      isolatedModules: false,
      sourceMap: false,
    },
    fileName: absPath,
    reportDiagnostics: false,
  });
  const jsCode = transpiled.outputText;

  const moduleShim: { exports: Record<string, unknown> } = { exports: {} };
  const dir = dirname(absPath);
  const fixtureRequire = createRequire(absPath);

  const wrappedSource =
    `(function (exports, require, module, __filename, __dirname, Buffer) {\n${jsCode}\n});`;
  const script = new vm.Script(wrappedSource, { filename: absPath });
  const wrappedFn = script.runInThisContext();
  wrappedFn.call(
    moduleShim.exports,
    moduleShim.exports,
    (mod: string) => {
      // Type-only imports are emitted to nothing, but the fixture might pull
      // in a real runtime module (e.g. "node:buffer"). Route through the
      // fixture's own require so path resolution matches the original file.
      try {
        return fixtureRequire(mod);
      } catch {
        return require_(mod);
      }
    },
    moduleShim,
    absPath,
    dir,
    Buffer,
  );
  return moduleShim.exports;
}

export function loadFixture(absPath: string): LoadedFixture {
  const text = readFileSync(absPath, "utf8");
  const filename = basename(absPath);
  const kind = classifyFixture(text, filename);

  const buildContext = (): AnalysisContext => {
    return buildContextFromSource(text, absPath, kind);
  };

  return { absPath, filename, text, kind, buildContext };
}

/**
 * Build an `AnalysisContext` from fixture source text. Used for both the
 * baseline (unmutated) and the mutated variants. The fixture is evaluated
 * in a fresh vm sandbox every call — no caching — so mutated vs. original
 * runs don't leak state.
 */
export function buildContextFromSource(
  source: string,
  absPath: string,
  kind?: FixtureKind,
): AnalysisContext {
  const actualKind = kind ?? classifyFixture(source, basename(absPath));

  if (actualKind === "raw-source" || actualKind === "unknown") {
    // Strip the `__fixtures__/` and `__tests__/` path segments from the
    // synthesized file path: several rules (K3, K5, K8, O4, M-series) use
    // those segments as a "skip, this is a test file" heuristic in their
    // gather step. The rule's OWN test harness passes `src/${name}` for
    // exactly this reason. The mutation runner mirrors that convention so
    // fixtures fire on the baseline instead of being skipped as test files.
    const virtualPath = `src/${basename(absPath)}`;
    const sourceFiles = new Map<string, string>();
    sourceFiles.set(virtualPath, source);
    return {
      server: {
        id: `mutation-${basename(absPath, ".ts")}`,
        name: "mutation-fixture",
        description: null,
        github_url: null,
      },
      tools: [],
      source_code: source,
      source_files: sourceFiles,
      dependencies: [],
      connection_metadata: null,
    };
  }

  if (actualKind === "context-build") {
    const exports = evaluateModule(source, absPath);
    const fn = exports["buildContext"];
    if (typeof fn !== "function") {
      throw new Error(`fixture ${basename(absPath)} declares buildContext but the evaluated export is not a function`);
    }
    const ctx = fn() as AnalysisContext;
    return ctx;
  }

  if (actualKind === "context-const") {
    const exports = evaluateModule(source, absPath);
    const f = exports["fixture"];
    if (!f || typeof f !== "object") {
      throw new Error(`fixture ${basename(absPath)} declares const fixture but the evaluated export is not an object`);
    }
    return f as AnalysisContext;
  }

  if (actualKind === "tool-const") {
    const exports = evaluateModule(source, absPath);
    const f = exports["fixture"] as
      | { name: string; description: string; input_schema: unknown }
      | undefined;
    if (!f || typeof f !== "object") {
      throw new Error(`fixture ${basename(absPath)} declares const fixture (tool-shaped) but evaluated export is not an object`);
    }
    return {
      server: {
        id: `mutation-${basename(absPath, ".ts")}`,
        name: "mutation-fixture",
        description: null,
        github_url: null,
      },
      tools: [
        {
          name: String(f.name ?? "unnamed"),
          description: f.description == null ? null : String(f.description),
          input_schema: (f.input_schema ?? null) as Record<string, unknown> | null,
        },
      ],
      source_code: null,
      dependencies: [],
      connection_metadata: null,
    };
  }

  if (actualKind === "source-string-const") {
    const exports = evaluateModule(source, absPath);
    const s = exports["source"];
    if (typeof s !== "string") {
      throw new Error(`fixture ${basename(absPath)} declares const source but evaluated export is not a string`);
    }
    const virtualPath = `src/${basename(absPath)}`;
    const sourceFiles = new Map<string, string>();
    sourceFiles.set(virtualPath, s);
    return {
      server: {
        id: `mutation-${basename(absPath, ".ts")}`,
        name: "mutation-fixture",
        description: null,
        github_url: null,
      },
      tools: [],
      source_code: s,
      source_files: sourceFiles,
      dependencies: [],
      connection_metadata: null,
    };
  }

  throw new Error(`unclassifiable fixture: ${absPath}`);
}

/**
 * Enumerate every true-positive fixture file for a given rule directory.
 * Returns absolute paths in stable (sorted) order.
 */
export function listTruePositiveFixtures(ruleDir: string): string[] {
  const fixturesDir = join(ruleDir, "__fixtures__");
  if (!existsSync(fixturesDir)) return [];
  // Defer node:fs.readdir to the caller to keep this function side-effect free
  // for tests — but we actually need the listing here, so use readdirSync
  // directly.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { readdirSync } = require_("node:fs");
  const entries = readdirSync(fixturesDir) as string[];
  return entries
    .filter((n) => n.startsWith("true-positive-") && n.endsWith(".ts"))
    .sort()
    .map((n) => join(fixturesDir, n));
}
