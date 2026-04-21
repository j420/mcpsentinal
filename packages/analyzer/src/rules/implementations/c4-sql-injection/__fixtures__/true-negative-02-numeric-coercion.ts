// True negative: numeric coercion (Number) IS on the C4 charter list as a
// weak-but-valid sanitiser for numeric columns. The chain still fires but
// drops to severity "informational" — not "critical" — so the critical
// filter used by the test suite sees zero findings.
import { createPool } from "mysql2";
const pool = createPool({ host: "db.example.com" });

export async function findUserById(req: { body: { id: string } }) {
  const id = Number(req.body.id);
  return pool.query(`SELECT * FROM users WHERE id = ${id}`);
}
