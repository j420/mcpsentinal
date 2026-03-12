import pino from "pino";
import { migrate } from "./migrate.js";
import { seed } from "./seed.js";
import pg from "pg";

const logger = pino({ name: "db:reset" });

async function reset(connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();

  try {
    logger.info("Dropping all tables...");
    await client.query(`
      DROP TABLE IF EXISTS score_history CASCADE;
      DROP TABLE IF EXISTS incidents CASCADE;
      DROP TABLE IF EXISTS dependencies CASCADE;
      DROP TABLE IF EXISTS sources CASCADE;
      DROP TABLE IF EXISTS scores CASCADE;
      DROP TABLE IF EXISTS findings CASCADE;
      DROP TABLE IF EXISTS scans CASCADE;
      DROP TABLE IF EXISTS parameters CASCADE;
      DROP TABLE IF EXISTS tools CASCADE;
      DROP TABLE IF EXISTS servers CASCADE;
      DROP TABLE IF EXISTS _migrations CASCADE;
    `);
    logger.info("All tables dropped");
  } finally {
    await client.end();
  }

  await migrate(connectionString);
  await seed(connectionString);
  logger.info("Database reset complete");
}

const dbUrl = process.env.DATABASE_URL;
if (dbUrl) {
  reset(dbUrl).catch((err) => {
    logger.error(err, "Reset failed");
    process.exit(1);
  });
}
