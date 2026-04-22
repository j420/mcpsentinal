/**
 * Q3 TN-01 — No network binding anywhere.
 * Expected: 0 findings (honest refusal — skip-when-no-network-binding).
 */
export function pureLogic(args: { a: number; b: number }) {
  return args.a + args.b;
}
