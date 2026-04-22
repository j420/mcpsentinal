// True positive: lodash _.merge with user-controlled req.body input.
// Classic CVE-2019-10744 shape — no guard, no Object.create(null) target.
import _ from "lodash";

const defaults = { timeout: 30, retries: 3 };

export function configure(req: { body: { settings: Record<string, unknown> } }) {
  return _.merge(defaults, req.body.settings);
}
