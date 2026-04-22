// True negative: a charter-audited sanitiser wraps the error before it
// reaches the response. The sanitiser is responsible for redacting
// stack and internal fields.
import { sanitizeError } from "./safe-error.js";

export function handleSanitised(req: { body: unknown }, res: { json: (body: unknown) => void }) {
  try {
    JSON.parse(JSON.stringify(req.body));
  } catch (err) {
    res.json({ ok: false, error: sanitizeError(err) });
  }
}
