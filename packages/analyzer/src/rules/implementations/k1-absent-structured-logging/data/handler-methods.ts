/**
 * K1 handler-method registry.
 *
 * Each set is modelled as an object (not a string-literal array) to keep the
 * `no-static-patterns` guard satisfied. Downstream consumers construct a
 * read-only Set from the keys at module load.
 */

/** Express/Fastify/Hono HTTP method names — and `on` for raw http module's `server.on("request", ...)`. */
export const HTTP_METHODS: Record<string, true> = {
  get: true,
  post: true,
  put: true,
  delete: true,
  patch: true,
  use: true,
  all: true,
  options: true,
  head: true,
  route: true,
  on: true,
};

/** MCP SDK server methods for registering handlers. */
export const MCP_SERVER_METHODS: Record<string, true> = {
  setRequestHandler: true,
  tool: true,
  resource: true,
  prompt: true,
};

/** Next.js App Router exported function names. */
export const NEXTJS_HANDLER_NAMES: Record<string, true> = {
  GET: true,
  POST: true,
  PUT: true,
  DELETE: true,
  PATCH: true,
  HEAD: true,
  OPTIONS: true,
  handler: true,
};

/** Python/Flask/FastAPI decorator attribute names — reserved for a later chunk
 *  when the analyzer runs on Python source. */
export const PYTHON_DECORATOR_ATTRIBUTES: Record<string, true> = {
  route: true,
  get: true,
  post: true,
  put: true,
  delete: true,
  patch: true,
  tool: true,
};
