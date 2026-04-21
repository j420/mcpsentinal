// True positive: template-literal substitution in db.query().
// Source → sink on the same line — "trivial" exploitability.
import { createPool } from "mysql2";
const pool = createPool({ host: "db.example.com" });

export async function lookupUser(req: { body: { name: string } }) {
  const name = req.body.name;
  return pool.query(`SELECT * FROM users WHERE name = '${name}'`);
}
