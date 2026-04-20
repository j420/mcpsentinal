/**
 * K4 TP-01 — an Express handler whose destructive path has no guard.
 *
 * Expected behaviour:
 *   - `db.deleteAll(...)` is classified destructive via tokens [delete, All]
 *   - bulk marker present (`All`)
 *   - ancestor walk from the call to the enclosing function body finds
 *     NO IfStatement with a guard condition, no confirmation call,
 *     no receiver-method guard
 *   - rule fires with high confidence; bulk factor applied
 */

import express from "express";
const app = express();
const db = { deleteAll(_opts: { table: string }) { /* real handler */ } };

app.post("/cleanup", async (req, _res) => {
  await db.deleteAll({ table: req.body.table });
});
