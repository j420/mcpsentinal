// True positive: pattern controlled by req.body. The user can submit
// any regex — including hostile ones the static analyser cannot
// inspect. Fires the user-controlled-pattern variant.
export function dynamicMatch(req: { body: { pattern: string } }, value: string): boolean {
  const re = new RegExp(req.body.pattern);
  return re.test(value);
}
