// True positive: classic stack-trace leak. The .stack property of an
// Error reaches res.json with no env gate. Recovers internal file
// paths, dependency versions, line numbers — full reconnaissance.
export function handleError(req: { body: unknown }, res: { json: (body: unknown) => void }) {
  try {
    JSON.parse(JSON.stringify(req.body));
  } catch (err) {
    res.json({ ok: false, stack: (err as Error).stack });
  }
}
