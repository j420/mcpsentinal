export const N13_CONFIDENCE_CAP = 0.82;

export const SMUGGLE_FRAGMENTS: Readonly<Record<string, string>> = {
  "transfer-encoding: chunked": "chunked Transfer-Encoding header",
  "transfer-encoding':'chunked": "chunked Transfer-Encoding header (quoted)",
  "content-length": "Content-Length header assignment",
  "\\r\\n0\\r\\n": "raw chunked terminator literal",
  "chunk-extension": "chunk-extension abuse",
};

export const TRANSPORT_MARKER_FRAGMENTS: Readonly<Record<string, string>> = {
  streamable: "Streamable HTTP transport",
  eventsource: "EventSource / SSE",
  "text/event-stream": "text/event-stream content-type",
  createserver: "http.createServer / express createServer",
  "net.socket": "net.Socket raw socket",
};

/** Library / framework markers that indicate the server uses a well-tested HTTP stack. */
export const SAFE_STACK_MARKERS: Readonly<Record<string, string>> = {
  express: "express framework",
  koa: "koa framework",
  fastify: "fastify framework",
  hapi: "hapi framework",
  undici: "undici HTTP client",
};
