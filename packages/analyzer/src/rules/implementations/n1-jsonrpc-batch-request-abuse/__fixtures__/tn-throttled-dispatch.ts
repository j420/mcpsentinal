/**
 * True negative: iteration wrapped in a throttle()/rateLimit() primitive.
 * The enclosing function contains throttle vocabulary, so the rule must
 * suppress the finding.
 */

function throttle<T extends (...args: any[]) => void>(fn: T, _ms: number): T { return fn; }

export function handleStream(batch: unknown[]): void {
  const throttled = throttle((m: unknown) => process(m), 100);
  batch.forEach((msg) => throttled(msg));
}

function process(_msg: unknown): void {
  // noop
}
