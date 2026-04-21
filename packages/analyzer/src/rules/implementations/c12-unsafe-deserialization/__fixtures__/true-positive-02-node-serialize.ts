// True positive: require('node-serialize').unserialize with user input —
// the exact shape of CVE-2017-5941.
import { unserialize } from "node-serialize";

export async function rehydrate(req: { body: { payload: string } }) {
  const payload = req.body.payload;
  return unserialize(payload);
}
