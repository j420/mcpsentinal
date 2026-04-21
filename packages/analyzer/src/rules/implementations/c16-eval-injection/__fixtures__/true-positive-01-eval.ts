// True positive: eval() with direct user input.
export function evaluate(req: { body: { expr: string } }) {
  const expr = req.body.expr;
  return eval(expr);
}
