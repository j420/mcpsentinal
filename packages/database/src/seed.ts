import pg from "pg";
import pino from "pino";

const logger = pino({ name: "db:seed" });

const SEED_SERVERS = [
  {
    name: "mcp-server-postgres",
    slug: "mcp-server-postgres",
    description: "MCP server for PostgreSQL database access",
    author: "modelcontextprotocol",
    github_url: "https://github.com/modelcontextprotocol/servers",
    npm_package: "@modelcontextprotocol/server-postgres",
    category: "database",
    language: "TypeScript",
    license: "MIT",
    github_stars: 5000,
  },
  {
    name: "mcp-server-filesystem",
    slug: "mcp-server-filesystem",
    description: "MCP server providing filesystem access",
    author: "modelcontextprotocol",
    github_url: "https://github.com/modelcontextprotocol/servers",
    npm_package: "@modelcontextprotocol/server-filesystem",
    category: "filesystem",
    language: "TypeScript",
    license: "MIT",
    github_stars: 5000,
  },
  {
    name: "mcp-server-github",
    slug: "mcp-server-github",
    description: "MCP server for GitHub API integration",
    author: "modelcontextprotocol",
    github_url: "https://github.com/modelcontextprotocol/servers",
    npm_package: "@modelcontextprotocol/server-github",
    category: "api-integration",
    language: "TypeScript",
    license: "MIT",
    github_stars: 5000,
  },
  {
    name: "mcp-server-brave-search",
    slug: "mcp-server-brave-search",
    description: "MCP server for Brave Search API",
    author: "modelcontextprotocol",
    github_url: "https://github.com/modelcontextprotocol/servers",
    npm_package: "@modelcontextprotocol/server-brave-search",
    category: "search",
    language: "TypeScript",
    license: "MIT",
    github_stars: 5000,
  },
  {
    name: "mcp-server-sqlite",
    slug: "mcp-server-sqlite",
    description: "MCP server for SQLite database operations",
    author: "modelcontextprotocol",
    github_url: "https://github.com/modelcontextprotocol/servers",
    npm_package: "@modelcontextprotocol/server-sqlite",
    category: "database",
    language: "TypeScript",
    license: "MIT",
    github_stars: 5000,
  },
];

export async function seed(connectionString: string): Promise<void> {
  const client = new pg.Client({ connectionString });
  await client.connect();

  try {
    for (const server of SEED_SERVERS) {
      await client.query(
        `INSERT INTO servers (name, slug, description, author, github_url, npm_package, category, language, license, github_stars)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (slug) DO NOTHING`,
        [
          server.name,
          server.slug,
          server.description,
          server.author,
          server.github_url,
          server.npm_package,
          server.category,
          server.language,
          server.license,
          server.github_stars,
        ]
      );
      logger.info({ server: server.name }, "Seeded server");
    }

    logger.info(`Seeded ${SEED_SERVERS.length} servers`);
  } finally {
    await client.end();
  }
}

const dbUrl = process.env.DATABASE_URL;
if (dbUrl) {
  seed(dbUrl).catch((err) => {
    logger.error(err, "Seed failed");
    process.exit(1);
  });
}
