/**
 * L2 — Malicious Build Plugin: deterministic fact gatherer.
 *
 * Three inputs are inspected (each independent — a rule can fire on
 * any of them):
 *
 *   1. package.json scripts — parsed via JSON.parse; each install-hook
 *      body (preinstall / install / postinstall / prepare) is scanned
 *      for danger tokens.
 *   2. Build-config files (rollup/vite/webpack/esbuild) — parsed via
 *      the TypeScript compiler API. The walker finds function literals
 *      attached to hook names and inspects their body for dangerous
 *      API invocations.
 *   3. ESM URL imports in any build-config file — `import X from
 *      "https://..."` is flagged regardless of what the imported module
 *      does.
 *
 * No regex literals. All vocabularies live under `./data/`.
 */

import ts from "typescript";
import type { AnalysisContext } from "../../../engine.js";
import type { Location } from "../../location.js";
import {
  PLUGIN_HOOK_NAMES,
  DANGEROUS_APIS,
  BUILD_CONFIG_FILE_MARKERS,
  INSTALL_HOOK_KEYS,
  INSTALL_HOOK_DANGER_TOKENS,
  INSTALL_HOOK_ENV_GATES,
  SENSITIVE_ENV_VAR_NAMES,
  type DangerousApi,
} from "./data/plugin-vocabulary.js";

// ─── Fact types ────────────────────────────────────────────────────────────

export type L2FindingKind =
  | "install-hook-dangerous"
  | "plugin-hook-dangerous-api"
  | "dynamic-plugin-load"
  | "url-plugin-import";

export interface L2Fact {
  /** Which kind of finding this is. */
  kind: L2FindingKind;
  /** Config-kind for package.json hooks; source-kind for build-config ASTs. */
  location: Location;
  /** The offending text snippet (truncated). */
  observed: string;
  /** Human description. */
  description: string;
  /** Dangerous API details — present for plugin-hook-dangerous-api only. */
  api: DangerousApi | null;
  /** Hook name (generateBundle, postinstall, ...) — empty when not applicable. */
  hookName: string;
  /** Filename the evidence came from. */
  file: string;
  /** Whether a sensitive env-var read appears near the dangerous API call. */
  readsSensitiveEnv: boolean;
}

export interface L2GatherResult {
  mode: "absent" | "facts";
  facts: L2Fact[];
}

// ─── Top-level gather ──────────────────────────────────────────────────────

export function gatherL2(context: AnalysisContext): L2GatherResult {
  const files = collectFiles(context);
  const facts: L2Fact[] = [];

  for (const [file, text] of files) {
    if (isTestFileShape(file, text)) continue;
    if (isPackageJsonPath(file)) {
      facts.push(...scanPackageJson(file, text));
    } else if (isBuildConfigPath(file)) {
      facts.push(...scanBuildConfig(file, text));
    } else if (looksLikePackageJson(text)) {
      facts.push(...scanPackageJson(file, text));
    } else if (looksLikeBuildConfig(text)) {
      facts.push(...scanBuildConfig(file, text));
    }
  }

  return { mode: facts.length > 0 ? "facts" : "absent", facts };
}

function collectFiles(context: AnalysisContext): Map<string, string> {
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

function isPackageJsonPath(file: string): boolean {
  return file.endsWith("package.json");
}

function isBuildConfigPath(file: string): boolean {
  for (const marker of BUILD_CONFIG_FILE_MARKERS) {
    if (file.includes(marker)) return true;
  }
  return false;
}

function looksLikePackageJson(text: string): boolean {
  try {
    const parsed = JSON.parse(text);
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      (typeof (parsed as { scripts?: unknown }).scripts === "object" ||
        typeof (parsed as { dependencies?: unknown }).dependencies === "object")
    );
  } catch {
    return false;
  }
}

function looksLikeBuildConfig(text: string): boolean {
  for (const marker of BUILD_CONFIG_FILE_MARKERS) {
    if (text.includes(marker)) return true;
  }
  // Fallback: if the text declares a `plugins:` literal AND uses a common
  // plugin hook name, assume it's a build config.
  if (text.includes("plugins")) {
    for (const hook of PLUGIN_HOOK_NAMES) {
      if (text.includes(hook)) return true;
    }
  }
  return false;
}

function isTestFileShape(file: string, text: string): boolean {
  if (file.endsWith(".test.ts") || file.endsWith(".test.js")) return true;
  if (file.endsWith(".spec.ts") || file.endsWith(".spec.js")) return true;
  if (file.includes("__tests__/")) return true;
  // Avoid flagging a fixture suite that just happens to import vitest:
  // require BOTH an import AND a describe() top-level call.
  const hasRunner =
    text.includes('from "vitest"') ||
    text.includes('from "jest"') ||
    text.includes('from "mocha"');
  const hasSuite = text.includes("describe(");
  return hasRunner && hasSuite;
}

// ─── package.json scan ─────────────────────────────────────────────────────

function scanPackageJson(file: string, text: string): L2Fact[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  if (typeof parsed !== "object" || parsed === null) return [];
  const scripts = (parsed as { scripts?: Record<string, unknown> }).scripts;
  if (!scripts || typeof scripts !== "object") return [];

  const out: L2Fact[] = [];
  for (const hook of INSTALL_HOOK_KEYS) {
    const body = (scripts as Record<string, unknown>)[hook];
    if (typeof body !== "string" || body.length === 0) continue;

    const danger = firstMatch(body, INSTALL_HOOK_DANGER_TOKENS);
    if (!danger) continue;

    const gated = INSTALL_HOOK_ENV_GATES.some((g) => body.includes(g));
    out.push({
      kind: "install-hook-dangerous",
      location: {
        kind: "config",
        file,
        json_pointer: `/scripts/${escapePointer(hook)}`,
      },
      observed: body.slice(0, 240),
      description: gated
        ? `Install hook '${hook}' gated on an environment variable (CI/GITHUB_ACTIONS/process.env) still contains a fetch-and-exec primitive (${danger}). Static reviewers may miss the gate but CI runners match it.`
        : `Install hook '${hook}' contains a fetch-and-exec primitive (${danger}) — classic supply-chain RCE surface.`,
      api: null,
      hookName: hook,
      file,
      readsSensitiveEnv: SENSITIVE_ENV_VAR_NAMES.has(
        // read at install time uses shell substitution, not process.env; we
        // approximate by seeing if the body mentions any sensitive env var
        // name directly.
        firstEnvVar(body) ?? "",
      ),
    });
  }
  return out;
}

function firstMatch(body: string, tokens: readonly string[]): string | null {
  for (const t of tokens) {
    if (body.includes(t)) return t;
  }
  return null;
}

function firstEnvVar(body: string): string | null {
  for (const name of SENSITIVE_ENV_VAR_NAMES) {
    if (body.includes(name)) return name;
  }
  return null;
}

// ─── build-config AST scan ─────────────────────────────────────────────────

function scanBuildConfig(file: string, text: string): L2Fact[] {
  let sf: ts.SourceFile;
  try {
    sf = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true);
  } catch {
    return [];
  }

  const out: L2Fact[] = [];

  // Pass 1: URL-based imports / requires.
  ts.forEachChild(sf, function visit(node) {
    const urlImport = detectUrlImport(node, sf, file);
    if (urlImport) out.push(urlImport);

    const dynamicLoad = detectDynamicPluginLoad(node, sf, file);
    if (dynamicLoad) out.push(dynamicLoad);

    ts.forEachChild(node, visit);
  });

  // Pass 2: hook literals with dangerous-API bodies.
  ts.forEachChild(sf, function visit(node) {
    const hookFact = detectDangerousHookBody(node, sf, file);
    out.push(...hookFact);
    ts.forEachChild(node, visit);
  });

  return out;
}

function detectUrlImport(node: ts.Node, sf: ts.SourceFile, file: string): L2Fact | null {
  if (
    ts.isImportDeclaration(node) &&
    ts.isStringLiteral(node.moduleSpecifier) &&
    isHttpUrl(node.moduleSpecifier.text)
  ) {
    const { line, col } = toLineCol(sf, node.getStart(sf));
    return {
      kind: "url-plugin-import",
      location: { kind: "source", file, line, col },
      observed: node.moduleSpecifier.text.slice(0, 200),
      description:
        "Build config imports a module from an HTTP(S) URL — the code is not in the project's dependency tree and cannot be audited via npm audit / pnpm audit.",
      api: null,
      hookName: "",
      file,
      readsSensitiveEnv: false,
    };
  }
  if (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    (node.expression.text === "require" || node.expression.text === "import")
  ) {
    const first = node.arguments[0];
    if (first && ts.isStringLiteral(first) && isHttpUrl(first.text)) {
      const { line, col } = toLineCol(sf, node.getStart(sf));
      return {
        kind: "url-plugin-import",
        location: { kind: "source", file, line, col },
        observed: first.text.slice(0, 200),
        description:
          "Build config require/import resolves to an HTTP(S) URL — the code is not in the project's dependency tree.",
        api: null,
        hookName: "",
        file,
        readsSensitiveEnv: false,
      };
    }
  }
  return null;
}

function detectDynamicPluginLoad(node: ts.Node, sf: ts.SourceFile, file: string): L2Fact | null {
  if (
    ts.isCallExpression(node) &&
    ts.isIdentifier(node.expression) &&
    (node.expression.text === "require" || node.expression.text === "import")
  ) {
    const first = node.arguments[0];
    if (!first) return null;
    // Literal — handled by detectUrlImport.
    if (ts.isStringLiteral(first) || ts.isNoSubstitutionTemplateLiteral(first)) {
      return null;
    }
    // Non-literal argument → dynamic.
    const { line, col } = toLineCol(sf, node.getStart(sf));
    return {
      kind: "dynamic-plugin-load",
      location: { kind: "source", file, line, col },
      observed: node.getText(sf).slice(0, 200),
      description:
        "Build config performs a require/import with a non-literal argument — plugin identity is resolved at build time from a variable, preventing static audit.",
      api: null,
      hookName: "",
      file,
      readsSensitiveEnv: false,
    };
  }
  return null;
}

/**
 * Find a function literal attached to a plugin-hook property name
 * (e.g., `generateBundle(bundle) { fs.writeFileSync(...) }`). For each
 * such function, walk its body and emit a fact for every dangerous API
 * call found inside.
 */
function detectDangerousHookBody(node: ts.Node, sf: ts.SourceFile, file: string): L2Fact[] {
  // Property assignments: `generateBundle: (bundle) => { ... }` or
  // `generateBundle(bundle) { ... }` (shorthand method).
  if (ts.isPropertyAssignment(node) || ts.isMethodDeclaration(node) || ts.isShorthandPropertyAssignment(node)) {
    const name = getPropertyName(node);
    if (name && PLUGIN_HOOK_NAMES.has(name)) {
      const body = getFunctionBody(node);
      if (body) {
        return dangerousCallsInBody(body, sf, file, name);
      }
    }
  }
  return [];
}

function getPropertyName(
  node: ts.PropertyAssignment | ts.MethodDeclaration | ts.ShorthandPropertyAssignment,
): string | null {
  if (ts.isPropertyAssignment(node) || ts.isMethodDeclaration(node)) {
    const name = node.name;
    if (ts.isIdentifier(name) || ts.isStringLiteral(name)) return name.text;
    return null;
  }
  return ts.isIdentifier(node.name) ? node.name.text : null;
}

function getFunctionBody(
  node: ts.PropertyAssignment | ts.MethodDeclaration | ts.ShorthandPropertyAssignment,
): ts.Node | null {
  if (ts.isMethodDeclaration(node)) return node.body ?? null;
  if (ts.isPropertyAssignment(node)) {
    const init = node.initializer;
    if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) {
      return init.body;
    }
  }
  return null;
}

function dangerousCallsInBody(
  body: ts.Node,
  sf: ts.SourceFile,
  file: string,
  hookName: string,
): L2Fact[] {
  const out: L2Fact[] = [];
  const bodyText = body.getText(sf);
  const envReadNearby = bodyText.includes("process.env");

  function visit(node: ts.Node): void {
    if (ts.isCallExpression(node)) {
      const apiName = resolveCalleeName(node);
      if (apiName && Object.prototype.hasOwnProperty.call(DANGEROUS_APIS, apiName)) {
        const api = DANGEROUS_APIS[apiName];
        const { line, col } = toLineCol(sf, node.getStart(sf));
        out.push({
          kind: "plugin-hook-dangerous-api",
          location: { kind: "source", file, line, col },
          observed: node.getText(sf).slice(0, 200),
          description:
            `Plugin hook '${hookName}' body invokes ${apiName}(...) — ${api.description}.`,
          api,
          hookName,
          file,
          readsSensitiveEnv: envReadNearby,
        });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(body);
  return out;
}

function resolveCalleeName(call: ts.CallExpression): string | null {
  const expr = call.expression;
  if (ts.isIdentifier(expr)) return expr.text;
  if (ts.isPropertyAccessExpression(expr)) {
    if (ts.isIdentifier(expr.name)) return expr.name.text;
  }
  return null;
}

// ─── small helpers ────────────────────────────────────────────────────────

function toLineCol(sf: ts.SourceFile, pos: number): { line: number; col: number } {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return { line: line + 1, col: character + 1 };
}

function isHttpUrl(s: string): boolean {
  return s.startsWith("http://") || s.startsWith("https://");
}

function escapePointer(segment: string): string {
  return segment.split("~").join("~0").split("/").join("~1");
}
