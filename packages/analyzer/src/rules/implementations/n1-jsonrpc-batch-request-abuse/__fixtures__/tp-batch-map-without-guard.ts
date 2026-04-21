/**
 * True positive: batch-named receiver walked with .map(), no size check,
 * no throttle, no slice. Direct amplification primitive.
 */

export function processAll(messages: unknown[], rpc: { method: (m: unknown) => unknown }) {
  const results = (messages as unknown as { map: (fn: (m: unknown) => unknown) => unknown[] }).map(
    (msg) => rpc.method(msg),
  );
  return results;
}

// A second handler to keep the gather step focused on the first match.
export function dispatcher(batch: unknown[]) {
  return (batch as unknown as { forEach: (fn: (m: unknown) => void) => void }).forEach(
    (m) => {
      void m;
    },
  );
}
