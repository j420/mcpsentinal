// True positive: object-spread copies every enumerable property of the
// error — message, stack, code, custom properties. A regex looking for
// `error.stack` would miss this; the AST detector recognises the
// SpreadAssignment.
export function handleSpread(req: { body: unknown }, res: { send: (body: unknown) => void }) {
  try {
    JSON.parse(String(req.body));
  } catch (error) {
    res.send({ ok: false, ...error });
  }
}
