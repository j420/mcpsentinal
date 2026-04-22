/**
 * O6 TP-03 — throw new Error carrying DB connection string + driver + dialect.
 * A malformed SQL input surfaces the connection target to the caller.
 * Expected: ≥1 finding.
 */
export function query(sql: string, pool: { connectionString: string; driver: string; dialect: string }) {
  if (!sql) {
    throw new Error(JSON.stringify({
      code: "EINVAL",
      connectionString: pool.connectionString,
      driver: pool.driver,
      dialect: pool.dialect,
    }));
  }
  return [];
}
