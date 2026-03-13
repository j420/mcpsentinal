import express, { type Express } from "express";
import cors from "cors";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries, ServerListQuerySchema, migrate } from "@mcp-sentinel/database";
import { createBadgeSvg } from "./badge.js";

const logger = pino({ name: "api" });

const app: Express = express();
app.use(cors());
app.use(express.json());
app.use((req, _res, next) => {
  logger.info({ method: req.method, url: req.url }, "request");
  next();
});

// Database connection
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
});
const db = new DatabaseQueries(pool);

// ─── Routes ──────────────────────────────────────────────────────────────────

// GET /api/v1/servers — Search and list servers
app.get("/api/v1/servers", async (req, res) => {
  try {
    const query = ServerListQuerySchema.parse(req.query);
    const result = await db.searchServers(query);
    res.json({
      data: result.servers,
      pagination: {
        total: result.total,
        page: result.page,
        limit: result.limit,
        pages: Math.ceil(result.total / result.limit),
      },
    });
  } catch (err) {
    if (err instanceof Error && err.name === "ZodError") {
      res.status(400).json({ error: "Invalid query parameters", details: err });
    } else {
      logger.error(err, "Server list error");
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// GET /api/v1/servers/:slug — Server detail
app.get("/api/v1/servers/:slug", async (req, res) => {
  try {
    const server = await db.findServerBySlug(req.params.slug);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    const [tools, findings] = await Promise.all([
      db.getToolsForServer(server.id),
      db.getFindingsForServer(server.id),
    ]);

    res.json({ data: { ...server, tools, findings } });
  } catch (err) {
    logger.error(err, "Server detail error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/servers/:slug/findings — Findings for a server
app.get("/api/v1/servers/:slug/findings", async (req, res) => {
  try {
    const server = await db.findServerBySlug(req.params.slug);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    const findings = await db.getFindingsForServer(server.id);
    res.json({ data: findings });
  } catch (err) {
    logger.error(err, "Findings error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/servers/:slug/history — Score history
app.get("/api/v1/servers/:slug/history", async (req, res) => {
  try {
    const server = await db.findServerBySlug(req.params.slug);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }

    const history = await db.getScoreHistory(server.id);
    res.json({ data: history });
  } catch (err) {
    logger.error(err, "History error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/servers/:slug/badge.svg — Dynamic badge
app.get("/api/v1/servers/:slug/badge.svg", async (req, res) => {
  try {
    const server = await db.findServerBySlug(req.params.slug);
    if (!server) {
      res.status(404).send(createBadgeSvg("MCP Sentinel", "not found", "#999"));
      return;
    }

    const score = server.latest_score;
    let color = "#999";
    let label = "unscanned";

    if (score !== null) {
      label = `${score}/100`;
      if (score >= 80) color = "#4c1";
      else if (score >= 60) color = "#dfb317";
      else if (score >= 40) color = "#fe7d37";
      else color = "#e05d44";
    }

    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.send(createBadgeSvg("MCP Sentinel", label, color));
  } catch (err) {
    logger.error(err, "Badge error");
    res.status(500).send(createBadgeSvg("MCP Sentinel", "error", "#999"));
  }
});

// GET /api/v1/ecosystem/stats — Ecosystem statistics
app.get("/api/v1/ecosystem/stats", async (_req, res) => {
  try {
    const stats = await db.getEcosystemStats();
    res.json({ data: stats });
  } catch (err) {
    logger.error(err, "Stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// Root
app.get("/", (_req, res) => {
  res.json({ name: "MCP Sentinel API", version: "1.0.0", docs: "/api/v1" });
});

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── Start ───────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT || "3100", 10);

async function start() {
  const dbUrl = process.env.DATABASE_URL;
  if (dbUrl) {
    try {
      await migrate(dbUrl);
      logger.info("Migrations complete");
    } catch (err) {
      logger.error(err, "Migration failed — continuing without migration");
    }
  } else {
    logger.warn("DATABASE_URL not set, skipping migrations");
  }

  app.listen(PORT, "0.0.0.0", () => {
    logger.info({ port: PORT }, "MCP Sentinel API started");
  });
}

start();

export { app };
