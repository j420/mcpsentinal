// True positive: alternation overlap (a|ab)+ — both branches match
// the same prefix; the engine tries every combination.
export function altMatch(input: string): boolean {
  const re = /^(a|ab)+$/;
  return re.test(input);
}
