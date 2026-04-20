/**
 * K4 TP-02 — bulk irrevocable call (`destroyBatch`) with no guard.
 *
 * `destroy` is an irrevocable verb; `Batch` is a bulk marker. Together
 * this is the highest-severity shape the rule recognises: no soft
 * marker to temper the finding, no guard anywhere on the path.
 */

const records = {
  destroyBatch(_ids: string[]): void {
    // real code path
  },
};

export function purgeExpired(ids: string[]): void {
  records.destroyBatch(ids);
}
