/**
 * True negative: the handler explicitly compares batch length against a
 * constant before iterating. Matches the "explicit size guard" mitigation
 * the charter requires the rule to respect.
 */

const MAX_BATCH = 25;

export function handleRpc(request: { batch?: unknown }): void {
  if (Array.isArray(request.batch)) {
    const batch = request.batch as unknown[];
    if (batch.length > MAX_BATCH) {
      throw new Error("Batch too large");
    }
    batch.forEach((msg) => process(msg));
  }
}

function process(_msg: unknown): void {
  // noop
}
