// True negative: anchored static character class. No nested quantifier,
// no alternation overlap, no polynomial blow-up.
export function safeMatch(input: string): boolean {
  const re = /^[a-z0-9_-]+$/;
  return re.test(input);
}
