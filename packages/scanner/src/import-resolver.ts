/**
 * Import Resolver — parses source file imports and resolves relative paths.
 *
 * Used by SourceFetcher to discover additional files to download from GitHub.
 * Only resolves relative imports (./utils, ../lib/db) — not node_modules or pip packages.
 * No dynamic imports (require(variable), __import__()).
 *
 * Scope limits:
 * - Max 10 files per server (direct imports only, not transitive)
 * - Max 200KB total source
 * - Only relative imports
 */

// Lightweight logger — avoids importing pino for a utility module
const logger = {
  debug(obj: Record<string, unknown>, msg: string) {
    if (process.env.DEBUG) console.error(`[import-resolver] ${msg}`, JSON.stringify(obj));
  },
};

/** Max files to resolve per entry point */
export const MAX_IMPORT_FILES = 10;

/** Max total bytes across all resolved files */
export const MAX_TOTAL_BYTES = 200_000;

export interface ResolvedImport {
  /** The import specifier as written in source (e.g., "./utils") */
  specifier: string;
  /** Resolved file path relative to repo root (e.g., "src/utils.ts") */
  resolvedPath: string;
  /** Symbols imported (for named imports), null for default/star imports */
  importedSymbols: string[] | null;
}

/**
 * Extract relative import specifiers from JavaScript/TypeScript source code.
 * Handles: import/export declarations, require() calls, dynamic import() statements.
 */
export function extractJSImports(source: string): string[] {
  const specifiers = new Set<string>();

  // ES module imports: import X from "./foo", import { X } from "./foo", import "./foo"
  const esImportRe = /(?:import|export)\s+(?:[\s\S]*?\s+from\s+)?['"](\.[^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = esImportRe.exec(source))) {
    specifiers.add(m[1]);
  }

  // CommonJS require: require("./foo"), require('./foo')
  const requireRe = /require\s*\(\s*['"](\.[^'"]+)['"]\s*\)/g;
  while ((m = requireRe.exec(source))) {
    specifiers.add(m[1]);
  }

  return [...specifiers];
}

/**
 * Extract relative import specifiers from Python source code.
 * Handles: from . import X, from .utils import X, from ..lib import X, import .X
 */
export function extractPythonImports(source: string): string[] {
  const specifiers = new Set<string>();

  // from .module import X, from ..module import X, from . import X
  const fromImportRe = /from\s+(\.+\w*(?:\.\w+)*)\s+import/g;
  let m: RegExpExecArray | null;
  while ((m = fromImportRe.exec(source))) {
    specifiers.add(m[1]);
  }

  return [...specifiers];
}

/**
 * Resolve a JS/TS import specifier to a file path relative to the repo root.
 *
 * Given entry point "src/index.ts" and specifier "./utils", tries:
 *   src/utils.ts, src/utils.js, src/utils/index.ts, src/utils/index.js
 *
 * @param entryDir - directory of the importing file (e.g., "src")
 * @param specifier - the import specifier (e.g., "./utils", "../lib/db")
 * @returns Array of candidate paths to try (caller fetches first that exists)
 */
export function resolveJSImportPaths(entryDir: string, specifier: string): string[] {
  const resolved = normalizePath(entryDir, specifier);
  if (!resolved) return [];

  // If specifier already has an extension, just return it
  if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(resolved)) {
    return [resolved];
  }

  // Try common extensions and index files
  return [
    `${resolved}.ts`,
    `${resolved}.tsx`,
    `${resolved}.js`,
    `${resolved}.jsx`,
    `${resolved}/index.ts`,
    `${resolved}/index.js`,
  ];
}

/**
 * Resolve a Python relative import specifier to a file path.
 *
 * Given entry "src/server.py" and specifier ".utils", tries:
 *   src/utils.py, src/utils/__init__.py
 *
 * Given "src/server.py" and specifier "..lib.db", tries:
 *   lib/db.py, lib/db/__init__.py
 */
export function resolvePythonImportPaths(entryDir: string, specifier: string): string[] {
  // Count leading dots for relative depth
  const dotsMatch = specifier.match(/^(\.+)/);
  if (!dotsMatch) return [];

  const dots = dotsMatch[1].length;
  const modulePart = specifier.slice(dots);

  // Go up (dots - 1) directories from entryDir
  let baseDir = entryDir;
  for (let i = 1; i < dots; i++) {
    const lastSlash = baseDir.lastIndexOf("/");
    if (lastSlash === -1) {
      baseDir = "";
      break;
    }
    baseDir = baseDir.slice(0, lastSlash);
  }

  if (!modulePart) {
    // "from . import X" — refers to __init__.py in the current package
    return [joinPath(baseDir, "__init__.py")];
  }

  // Convert dots to path separators: .utils.helpers → utils/helpers
  const modulePath = modulePart.replace(/\./g, "/");
  const resolved = joinPath(baseDir, modulePath);

  return [
    `${resolved}.py`,
    `${resolved}/__init__.py`,
  ];
}

/**
 * Given fetched entry point source, determine which additional files to fetch.
 * Returns a deduplicated list of candidate paths ordered by priority.
 */
export function resolveImportsFromSource(
  entryPath: string,
  source: string,
  language: "js" | "python"
): string[] {
  const entryDir = dirName(entryPath);
  const candidates: string[] = [];
  const seen = new Set<string>();

  const specifiers =
    language === "python"
      ? extractPythonImports(source)
      : extractJSImports(source);

  logger.debug(
    { entryPath, language, specifiers: specifiers.length },
    "Import specifiers extracted"
  );

  for (const spec of specifiers) {
    const paths =
      language === "python"
        ? resolvePythonImportPaths(entryDir, spec)
        : resolveJSImportPaths(entryDir, spec);

    for (const p of paths) {
      if (!seen.has(p) && p !== entryPath) {
        seen.add(p);
        candidates.push(p);
      }
    }
  }

  // Cap at MAX_IMPORT_FILES
  return candidates.slice(0, MAX_IMPORT_FILES * 3); // 3 candidates per import
}

// ─── Path Utilities ─────────────────────────────────────────────────────────

function dirName(filePath: string): string {
  const lastSlash = filePath.lastIndexOf("/");
  return lastSlash === -1 ? "" : filePath.slice(0, lastSlash);
}

function joinPath(dir: string, file: string): string {
  if (!dir) return file;
  return `${dir}/${file}`;
}

/**
 * Normalize a relative path from a directory.
 * Resolves ".." and "." segments. Returns null if path escapes repo root.
 */
function normalizePath(dir: string, specifier: string): string | null {
  const parts = (dir ? `${dir}/${specifier}` : specifier).split("/");
  const resolved: string[] = [];

  for (const part of parts) {
    if (part === "." || part === "") continue;
    if (part === "..") {
      if (resolved.length === 0) return null; // escapes root
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }

  return resolved.join("/") || null;
}
