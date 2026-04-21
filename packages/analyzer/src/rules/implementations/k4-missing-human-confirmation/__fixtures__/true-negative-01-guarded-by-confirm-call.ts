/**
 * K4 TN-01 — destructive call inside an IfStatement whose condition is a
 * `confirm(...)` call. The ancestor walk sees the guard; no finding.
 */

declare function confirm(msg: string): Promise<boolean>;
const db = { deleteAll(_opts: { table: string }): void { /* real */ } };

export async function cleanup(table: string): Promise<void> {
  if (await confirm(`Delete all rows in ${table}?`)) {
    db.deleteAll({ table });
  }
}
