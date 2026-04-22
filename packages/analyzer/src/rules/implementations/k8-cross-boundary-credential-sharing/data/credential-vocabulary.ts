/**
 * K8 vocabulary tables.
 */

export const CREDENTIAL_NAME_TOKENS: ReadonlySet<string> = new Set([
  "token",
  "secret",
  "api_key",
  "apikey",
  "password",
  "passwd",
  "credential",
  "auth",
  "bearer",
  "access_token",
  "accesstoken",
  "refresh_token",
  "session_token",
  "private_key",
  "privatekey",
  "client_secret",
]);

export const OUTBOUND_NETWORK_CALLEES: ReadonlySet<string> = new Set([
  "fetch",
  "axios",
  "got",
  "request",
  "httpRequest",
  "http.request",
  "https.request",
  "callTool",
  "invokeTool",
  "send",
  "post",
  "put",
  "patch",
]);

export const SHARED_STORE_CALLEES: ReadonlySet<string> = new Set([
  "set",
  "setex",
  "hset",
  "sadd",
  "lpush",
  "rpush",
  "publish",
  "sendMessage",
  "putItem",
  "putObject",
]);

export const EXEC_CALLEES: ReadonlySet<string> = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
  "execa",
]);

export const TOKEN_EXCHANGE_TOKENS: ReadonlySet<string> = new Set([
  "token_exchange",
  "tokenExchange",
  "rfc8693",
  "exchangeToken",
  "scopedDelegation",
]);

export const CREDENTIAL_HEADER_KEYS: ReadonlySet<string> = new Set([
  "authorization",
  "Authorization",
  "x-api-key",
  "X-Api-Key",
  "x-auth-token",
  "cookie",
  "Cookie",
]);
