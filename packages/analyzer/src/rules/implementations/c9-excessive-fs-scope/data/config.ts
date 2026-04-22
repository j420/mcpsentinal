/**
 * C9 — Excessive Filesystem Scope: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 */

/**
 * Method names whose first argument is a filesystem path. When the
 * path is the root literal "/", the call lists / reads / walks the
 * entire filesystem.
 */
export const FS_LIST_METHODS: ReadonlySet<string> = new Set([
  "readdir",
  "readdirSync",
  "glob",
  "globSync",
  "walk",
  "walkSync",
  "walkdir",
  "iterdir",
]);

/** Generic filesystem read methods. */
export const FS_READ_METHODS: ReadonlySet<string> = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "open",
  "openSync",
  "stat",
  "lstat",
]);

/** Working-directory change methods. */
export const CHDIR_METHODS: ReadonlySet<string> = new Set([
  "chdir",
]);

/**
 * Identifier names commonly used to declare a base / allowed path
 * for filesystem scope. An assignment `<name> = "/"` to one of
 * these is a leak.
 */
export const BASE_PATH_IDENTIFIER_NAMES: ReadonlySet<string> = new Set([
  "BASE_DIR",
  "baseDir",
  "rootDir",
  "rootPath",
  "allowedPath",
  "allowedPaths",
  "ROOT",
  "FILESYSTEM_ROOT",
]);

/** Root path literals that mean "the entire filesystem". */
export const ROOT_PATH_LITERALS: ReadonlySet<string> = new Set([
  "/",
  "/*",
  "/**",
  "/**/*",
]);

/** Path-clamp helpers that prove the scope is bounded. */
export const CHARTER_CLAMP_HELPERS: ReadonlySet<string> = new Set([
  "isSubpath",
  "resolveWithin",
  "safeJoin",
  "ensureInside",
  "validatePath",
]);
