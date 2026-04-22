/**
 * N10 — Typed vocabularies for incomplete-handshake DoS detection.
 */

export type HandshakeRole =
  | "server-accept"
  | "handshake-read"
  | "timeout-primitive"
  | "connection-limit";

/** Server-construction call names that create a connection-accepting listener. */
export const SERVER_ACCEPT_CONSTRUCTORS: Record<string, HandshakeRole> = {
  WebSocketServer: "server-accept",
  createServer: "server-accept",
  Server: "server-accept",
  listen: "server-accept",
  upgrade: "server-accept",
};

/** Handshake-read identifier names: methods/variables that await initialize. */
export const HANDSHAKE_READ_IDENTIFIERS: Record<string, HandshakeRole> = {
  initialize: "handshake-read",
  onmessage: "handshake-read",
  on_connection: "handshake-read",
  handleinitialize: "handshake-read",
  awaitinitialize: "handshake-read",
  readinitialize: "handshake-read",
};

/** Timeout primitives whose presence suppresses the finding. */
export const TIMEOUT_PRIMITIVES: Record<string, HandshakeRole> = {
  handshaketimeout: "timeout-primitive",
  headerstimeout: "timeout-primitive",
  requesttimeout: "timeout-primitive",
  keepalivetimeout: "timeout-primitive",
  settimeout: "timeout-primitive",
  abortsignal: "timeout-primitive",
  promiserace: "timeout-primitive",
  timeout: "timeout-primitive",
  deadline: "timeout-primitive",
};

/** Connection-limit primitives. */
export const CONNECTION_LIMITS: Record<string, HandshakeRole> = {
  maxconnections: "connection-limit",
  backlog: "connection-limit",
  max_connections: "connection-limit",
  maxclients: "connection-limit",
};
