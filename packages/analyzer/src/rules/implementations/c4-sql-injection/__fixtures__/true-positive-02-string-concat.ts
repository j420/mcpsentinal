// True positive: multi-hop flow — tainted value passes through a helper
// that returns a SQL fragment. The AST analyser traces the return through
// the helper's binding to the .query() sink.
import { Client } from "pg";
const client = new Client();

function buildWhere(userId: string): string {
  return "WHERE user_id = '" + userId + "'";
}

export async function findOrders(req: { body: { userId: string } }) {
  const userId = req.body.userId;
  const where = buildWhere(userId);
  return client.query("SELECT * FROM orders " + where);
}
