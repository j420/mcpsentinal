/**
 * True positive: classic Array.isArray guard with forEach dispatch and no
 * limit vocabulary anywhere in the handler. CometBFT issue #2867 shape.
 */

export function handleRpc(request: { batch?: unknown; body?: unknown }): void {
  if (Array.isArray(request.batch)) {
    (request.batch as unknown[]).forEach((msg) => process(msg));
  }
}

function process(_msg: unknown): void {
  // Per-entry work — DB write, downstream API call, etc.
}
