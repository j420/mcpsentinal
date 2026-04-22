/**
 * C7 — Wildcard CORS: rule-specific config data.
 *
 * Lives under `data/` so the no-static-patterns guard skips the directory.
 */

/**
 * Function names that, when called, configure CORS. Covers express
 * `cors`, koa-cors, fastify-cors register names, hono `cors`, etc.
 */
export const CORS_FUNCTION_NAMES: ReadonlySet<string> = new Set([
  "cors",
  "corsMiddleware",
  "enableCors",
]);

/**
 * Python decorator / class names that configure CORS app-wide.
 */
export const PYTHON_CORS_NAMES: ReadonlySet<string> = new Set([
  "CORS",
  "CORSMiddleware",
  "cross_origin",
]);

/**
 * Method names that, on a response object, set HTTP headers. The
 * wildcard literal as the value of Access-Control-Allow-Origin is
 * the leak.
 */
export const HEADER_SET_METHODS: ReadonlySet<string> = new Set([
  "setHeader",
  "set",
  "header",
  "append",
]);

/** Header name canonical form (case-insensitive comparison). */
export const ACAO_HEADER_NAME = "access-control-allow-origin";

/** Header name for the credentials flag. */
export const ACAC_HEADER_NAME = "access-control-allow-credentials";
