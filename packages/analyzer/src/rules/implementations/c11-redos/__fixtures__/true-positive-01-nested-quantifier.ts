// True positive: nested quantifier (a+)+ — canonical ReDoS antipattern.
// On input "aaaaaaaaaaaaaaaaaaaaaaaaa!" the engine enumerates every
// possible split between the inner and outer + and hangs.
export function badMatch(input: string): boolean {
  const re = /^(a+)+$/;
  return re.test(input);
}
