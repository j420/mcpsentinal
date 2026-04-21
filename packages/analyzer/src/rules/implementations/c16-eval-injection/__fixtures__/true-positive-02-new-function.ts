// True positive: new Function() with a user-controlled body string.
export function compile(req: { body: { code: string } }) {
  const code = req.body.code;
  const fn = new Function(code);
  return fn();
}
