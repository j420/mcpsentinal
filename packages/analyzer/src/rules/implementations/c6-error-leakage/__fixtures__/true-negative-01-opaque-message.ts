// True negative: opaque error envelope. Message is a string literal, no
// error binding flows into the response.
export function handleOpaque(req: { body: unknown }, res: { json: (body: unknown) => void }) {
  try {
    JSON.parse(JSON.stringify(req.body));
  } catch {
    res.json({ ok: false, message: "Internal server error" });
  }
}
