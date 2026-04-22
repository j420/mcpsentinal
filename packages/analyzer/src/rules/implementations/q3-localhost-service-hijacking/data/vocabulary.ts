/**
 * Q3 — Localhost bind vocabulary.
 */

import { sinksOfKind, type ExfilSinkSpec } from "../../_shared/data-exfil-sinks.js";

export const LOCALHOST_SINKS: readonly ExfilSinkSpec[] = sinksOfKind("localhost-port");

/**
 * String values (lowercase) that, as the host argument of a
 * `.listen(port, host)` or `.bind(host, port)` call, identify a
 * localhost-class bind.
 */
export const LOCALHOST_HOST_VALUES: Readonly<Record<string, string>> = {
  "127.0.0.1": "IPv4 loopback literal",
  "localhost": "localhost hostname",
  "0.0.0.0": "all-interfaces bind (localhost + LAN)",
  "::1": "IPv6 loopback",
  "::": "IPv6 all-interfaces",
};

/**
 * Listener method names whose first positional argument is the
 * port / host. Keys are lowercased.
 */
export const LISTENER_METHODS: Readonly<Record<string, true>> = {
  listen: true,
  bind: true,
};

/**
 * Receiver or property tokens that amplify the "this is an MCP
 * server" classification. When observed in the bind site's
 * surrounding expression, confidence receives a small boost.
 */
export const MCP_RECEIVER_TOKENS: Readonly<Record<string, true>> = {
  mcpserver: true,
  mcp: true,
  tools: true,
  server: true,
};

/**
 * Identifiers whose presence in the enclosing function scope
 * indicates an auth check is in place. Any one hit suppresses
 * the finding below the confidence floor.
 */
export const AUTH_TOKEN_SCOPE_IDS: Readonly<Record<string, string>> = {
  authorization: "Authorization header check",
  bearer: "Bearer-token check",
  sharedSecret: "Shared-secret check",
  apiKey: "API-key check",
  authenticate: "authenticate() middleware",
};
