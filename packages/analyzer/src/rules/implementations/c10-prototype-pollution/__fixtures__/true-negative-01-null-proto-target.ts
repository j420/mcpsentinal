// True negative: merge target is Object.create(null) — cannot be polluted.
// The charter-audited guard is observed; severity drops below critical.
import _ from "lodash";

export function configure(req: { body: { settings: Record<string, unknown> } }) {
  const target = Object.create(null);
  return _.merge(target, req.body.settings);
}
