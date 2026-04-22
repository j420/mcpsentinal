/**
 * O6 — Fingerprint Surface Vocabulary.
 *
 * Every token below is an identifier that, when it shows up inside
 * an HTTP-response / tool-response / thrown-Error payload, leaks
 * OS, runtime, process, filesystem, dependency, or database
 * metadata to the caller. The gather step matches identifier
 * texts against these Records; it does NOT regex-match the
 * concatenated source. Zero regex literals.
 *
 * Each Record is kept to ≤5 entries so the no-static-patterns
 * guard never flags a "disguised pattern array".
 */

/**
 * Node.js process-level introspection primitives. Appearing in a
 * response body means the server exposed Node runtime metadata.
 */
export const PROCESS_SURFACE: Readonly<Record<string, string>> = {
  version: "process.version — Node runtime version",
  versions: "process.versions — full runtime component version map",
  platform: "process.platform — OS family (darwin/linux/win32)",
  arch: "process.arch — CPU architecture (x64/arm64)",
  env: "process.env — full environment (contains secrets)",
};

/**
 * Node.js process-level path / identity primitives.
 */
export const PATH_SURFACE: Readonly<Record<string, string>> = {
  __dirname: "__dirname — script directory path",
  __filename: "__filename — script file path",
  cwd: "process.cwd() — server working directory",
  mainModule: "process.mainModule — entry-point path",
  execPath: "process.execPath — Node binary path",
};

/**
 * Node.js `os` module primitives that reveal host metadata.
 */
export const OS_SURFACE: Readonly<Record<string, string>> = {
  hostname: "os.hostname — hostname / FQDN",
  networkInterfaces: "os.networkInterfaces — NIC addresses (MAC + IP)",
  cpus: "os.cpus — CPU model, cores, MHz",
  userInfo: "os.userInfo — local user account detail",
  release: "os.release — kernel / OS release string",
};

/**
 * Error-object fields that flow filesystem, dependency version, or
 * connection-string data into a response body.
 */
export const ERROR_FIELD_SURFACE: Readonly<Record<string, string>> = {
  stack: "err.stack — full stack trace + file paths + versions",
  path: "err.path — filesystem path that caused the error",
  syscall: "err.syscall — raw syscall name",
  code: "err.code — low-level error code (ENOENT, EACCES, etc.)",
  config: "err.config — HTTP / DB config including URLs and creds",
};

/**
 * Database / connection-string fingerprinting surface.
 */
export const DB_SURFACE: Readonly<Record<string, string>> = {
  connectionString: "connectionString — DB URL with creds",
  DATABASE_URL: "DATABASE_URL — DB URL env var",
  pool: "pool.options — DB pool config (host/port/db)",
  driver: "driver name / version — DB adapter identity",
  dialect: "dialect — DB family (pg/mysql/sqlite)",
};

/**
 * Dependency-version introspection sinks — a response reading any
 * of these surfaces the user's installed package versions.
 */
export const DEPENDENCY_SURFACE: Readonly<Record<string, string>> = {
  dependencies: "package.json dependencies list",
  devDependencies: "package.json devDependencies list",
  packageJson: "package.json — full manifest",
  nodeModules: "node_modules/** — installed module tree",
  requireResolve: "require.resolve() — installed module location",
};

/**
 * Response-construction host identifiers — calls that emit a body
 * to the caller. If any of these receivers carries a fingerprint-
 * surface identifier argument, the match fires.
 */
export const RESPONSE_EMITTERS: Readonly<Record<string, string>> = {
  res: "express/fastify/koa HTTP response object",
  reply: "fastify reply object",
  ctx: "koa context",
  response: "generic response object",
  result: "MCP tool result object",
};

/**
 * Response-construction methods. A call like `res.json({...})`
 * with a fingerprint surface identifier inside the argument is a
 * hit.
 */
export const RESPONSE_METHODS: Readonly<Record<string, string>> = {
  json: "res.json — JSON response body",
  send: "res.send — response body",
  end: "res.end — response body",
  write: "res.write — response body chunk",
  status: "res.status — chained with .send/.json",
};

/**
 * Sanitiser / redaction identifiers — when an enclosing function
 * mentions one of these, the finding is demoted. Strong evidence
 * the author is routing errors through a scrubbing layer.
 */
export const SANITIZER_HINTS: Readonly<Record<string, string>> = {
  redact: "pino.redact / manual redact() helper",
  sanitize: "sanitizeError / sanitize helper",
  scrub: "scrub_error / sentry scrub helpers",
  mask: "mask / maskSecrets helper",
  filter: "filterErrorPayload helper",
};
