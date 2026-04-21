// True negative: JSON.parse is a data parser, not code evaluator.
// User input flows to JSON.parse and stops there — no eval-family sink.
export function parseData(req: { body: { json: string } }) {
  const json = req.body.json;
  return JSON.parse(json);
}
