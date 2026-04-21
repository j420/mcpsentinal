// True negative: JSON.parse on a string — JSON itself does not execute
// embedded code. No reviver is used, so class-resolution is not a risk
// (CHARTER edge case 3 covers reviver-based instantiation separately).
export function parse(req: { body: { payload: string } }) {
  const payload = req.body.payload;
  return JSON.parse(payload);
}
