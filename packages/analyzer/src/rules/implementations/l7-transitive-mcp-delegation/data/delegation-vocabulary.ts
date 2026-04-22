/**
 * L7 vocabulary tables — loaded by gather.ts at module init.
 *
 * Lives under `data/` (guard-skipped). All detection data that would
 * otherwise be a regex literal or long string array lives here, shaped
 * as typed `Record<string, ...>` or `ReadonlySet<string>` to stay under
 * the no-static-patterns guard's array-literal threshold.
 */

/**
 * MCP SDK subpath substrings that identify a CLIENT-side import. Any
 * import specifier whose text contains one of these substrings is a
 * client import.
 *
 * The SDK publishes subpath exports (`/client/index.js`,
 * `/client/stdio.js`, etc.) that are stable across the 1.x and
 * experimental 2.x lines — the substring match is therefore robust
 * against minor version bumps.
 */
export const MCP_CLIENT_SDK_SUBSTRINGS: ReadonlySet<string> = new Set([
  "@modelcontextprotocol/sdk/client",
  "@modelcontextprotocol/sdk-client",
]);

/**
 * MCP SDK subpath substrings that identify a SERVER-side import.
 * Presence of both a client and a server import in the same source
 * tree is the dual-SDK signal the rule turns on.
 */
export const MCP_SERVER_SDK_SUBSTRINGS: ReadonlySet<string> = new Set([
  "@modelcontextprotocol/sdk/server",
  "@modelcontextprotocol/sdk-server",
]);

/**
 * Proxy / bridge / gateway package names. Any import whose specifier
 * starts with one of these is equivalent to a client import for the
 * purposes of L7 detection — the package itself holds the transitive
 * connection.
 */
export const MCP_PROXY_FRAMEWORKS: ReadonlySet<string> = new Set([
  "mcp-proxy",
  "mcp-bridge",
  "mcp-gateway",
  "@modelcontextprotocol/proxy",
]);

/**
 * Transport class identifiers exported from the MCP client SDK. Any
 * `new <Transport>(...)` expression whose constructor was imported from
 * the MCP client SDK is equivalent to constructing a `Client` for the
 * purposes of the transitive-connection check.
 */
export const CLIENT_TRANSPORT_CLASSES: ReadonlySet<string> = new Set([
  "Client",
  "StdioClientTransport",
  "SSEClientTransport",
  "StreamableHTTPClientTransport",
  "WebSocketClientTransport",
]);

/**
 * Credential header names that, when taken from an incoming request
 * and placed onto an outgoing client call's headers, constitute the
 * credential-forwarding pattern.
 */
export const CREDENTIAL_HEADER_NAMES: ReadonlySet<string> = new Set([
  "authorization",
  "x-api-key",
  "x-auth-token",
  "cookie",
]);

/**
 * Property names whose presence on an object literal or an assignment
 * right-hand side indicates that an incoming-request credential is
 * being passed through. Used by the forwarding heuristic when a full
 * taint chain cannot be proved.
 */
export const CREDENTIAL_FORWARDING_HINTS: ReadonlySet<string> = new Set([
  "authorization",
  "Authorization",
  "bearer",
  "headers",
]);
