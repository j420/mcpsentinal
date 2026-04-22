/**
 * True positive — "batch-within-batch" lethal edge case. The outer payload
 * is a single object; the inner `.batch` array is the amplification vector.
 * A naive "check outer length" guard would miss this shape entirely.
 */

export function handleNested(payload: { batch?: unknown }): void {
  if (Array.isArray(payload.batch)) {
    (payload.batch as unknown[]).forEach((entry) => dispatch(entry));
  }
}

function dispatch(_entry: unknown): void {
  // noop
}
