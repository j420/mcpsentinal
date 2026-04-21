// True positive: literal critical-key write. The CODE itself is the
// vulnerability — the assignment mutates Object.prototype regardless
// of whether the value is tainted.
export function compromise(target: Record<string, unknown>, value: unknown) {
  target["__proto__"] = value;
}
