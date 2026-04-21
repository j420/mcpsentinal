// True positive: Object.assign with JSON.parse of an external request body.
// Matches the CHARTER edge case "Object.assign({}, JSON.parse(req.body))".
export function handler(req: { body: string }) {
  const target = {};
  const parsed = JSON.parse(req.body);
  return Object.assign(target, parsed);
}
