// True negative: parameterised query — the $1 placeholder means the driver
// sends the value as a typed parameter, not as SQL syntax.
import { Client } from "pg";
const client = new Client();

export async function findUserSafe(req: { body: { id: string } }) {
  const id = req.body.id;
  return client.query("SELECT * FROM users WHERE id = $1", [id]);
}
