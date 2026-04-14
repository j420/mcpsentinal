import express, { type Express, type Request, type Response, type NextFunction } from "express";
import cors from "cors";
import pg from "pg";
import pino from "pino";
import { z } from "zod";
import {
  DatabaseQueries,
  ServerListQuerySchema,
  ComplianceFrameworkId,
  migrate,
} from "@mcp-sentinel/database";
import type {
  ComplianceFindingRecord,
  ComplianceFrameworkId as ComplianceFrameworkIdType,
  Server,
} from "@mcp-sentinel/database";
import { RiskMatrixAnalyzer } from "@mcp-sentinel/risk-matrix";
import { createBadgeSvg } from "./badge.js";

// Log to stderr — keeps stdout clean for callers that parse it
const logger = pino({ name: "api" }, process.stderr);

const app: Express = express();

// ─── Security Headers (applied to every response) ────────────────────────────
// These defend against common browser-side attacks when the API or badge is
// loaded in a web context.
app.use((_req: Request, res: Response, next: NextFunction) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  // Disable browser features not needed for a read-only JSON API
  res.setHeader("Permissions-Policy", "interest-cohort=(), camera=(), microphone=()");
  next();
});

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Public read-only API — allow all origins, but restrict to safe methods.
// Preflight results are cached for 24 hours to reduce OPTIONS traffic.
app.use(
  cors({
    methods: ["GET", "HEAD", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Accept"],
    maxAge: 86400,
  })
);

app.use(express.json({ limit: "16kb" })); // Small limit — API only receives GET requests

// ─── Request Logging ──────────────────────────────────────────────────────────
app.use((req: Request, _res: Response, next: NextFunction) => {
  // Log IP for rate-limit debugging, but never log query parameters that
  // could inadvertently capture sensitive data.
  logger.info({ method: req.method, path: req.path }, "request");
  next();
});

// ─── Rate Limiter ────────────────────────────────────────────────────────────
// Simple in-memory sliding window: 100 requests per IP per minute.
// Not cluster-safe — single Railway instance is sufficient at current scale.
// Replace with Redis-backed limiter when deploying multiple instances.
const rateLimitStore = new Map<string, number[]>();
const RATE_WINDOW_MS = 60_000;
const RATE_MAX_REQUESTS = 100;
// Badge endpoints get a tighter limit — they are commonly embedded in pages
// and CDNs should absorb most badge traffic via Cache-Control.
const RATE_MAX_BADGE = 30;

// Periodic cleanup — prevent unbounded memory growth from unique IPs
setInterval(() => {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  for (const [ip, times] of rateLimitStore.entries()) {
    const recent = times.filter((t) => t > cutoff);
    if (recent.length === 0) {
      rateLimitStore.delete(ip);
    } else {
      rateLimitStore.set(ip, recent);
    }
  }
}, RATE_WINDOW_MS);

function checkRateLimit(ip: string, max: number): boolean {
  const now = Date.now();
  const cutoff = now - RATE_WINDOW_MS;
  const times = (rateLimitStore.get(ip) ?? []).filter((t) => t > cutoff);
  times.push(now);
  rateLimitStore.set(ip, times);
  return times.length <= max;
}

function rateLimitMiddleware(max = RATE_MAX_REQUESTS) {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Trust X-Forwarded-For only from Railway's proxy — use socket address as
    // the canonical IP to prevent IP spoofing via header injection.
    const ip = req.socket.remoteAddress ?? "unknown";
    if (!checkRateLimit(ip, max)) {
      res.status(429).json({
        error: "Too many requests. Please slow down.",
        retry_after_seconds: 60,
      });
      return;
    }
    next();
  };
}

// ─── Input Validation Helpers ─────────────────────────────────────────────────

// Slugs are auto-generated from server names: lowercase, hyphens, alphanumeric.
// Reject anything else before it reaches the database layer.
// Uppercase letters are rejected — all slugs are normalised to lowercase on ingest.
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,98}[a-z0-9]$|^[a-z0-9]$/;

function isValidSlug(slug: string): boolean {
  return (
    SLUG_RE.test(slug) &&
    !slug.includes("..") &&   // prevent path traversal attempts
    !slug.includes("/") &&    // no path separators
    !slug.includes("\x00")    // no null bytes
  );
}

// ─── Database ─────────────────────────────────────────────────────────────────
const dbUrl = process.env["DATABASE_URL"] ?? "";
const pool = new pg.Pool({
  connectionString: dbUrl,
  // Railway's managed PostgreSQL requires SSL for public proxy connections.
  // rejectUnauthorized is false here because Railway uses a shared certificate
  // that does not match the hostname. TODO: Migrate to Railway's private
  // networking (no public proxy) to enable full cert verification.
  ssl:
    dbUrl && !dbUrl.includes("localhost") && !dbUrl.includes("127.0.0.1")
      ? { rejectUnauthorized: false }
      : false,
  // Connection pool limits prevent DB exhaustion from traffic spikes
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});
const db = new DatabaseQueries(pool);

// ─── Routes ───────────────────────────────────────────────────────────────────

// GET /api/v1/servers — Search and list servers (paginated, filterable)
app.get("/api/v1/servers", rateLimitMiddleware(), async (req: Request, res: Response) => {
  const parsed = ServerListQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid query parameters", issues: parsed.error.issues });
    return;
  }
  try {
    const result = await db.searchServers(parsed.data);
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
    logger.error(err, "Server list error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/servers/:slug — Server detail
app.get("/api/v1/servers/:slug", rateLimitMiddleware(), async (req: Request, res: Response) => {
  const { slug } = req.params;
  if (!slug || !isValidSlug(slug)) {
    res.status(400).json({ error: "Invalid server slug" });
    return;
  }
  try {
    const server = await db.findServerBySlug(slug);
    if (!server) {
      res.status(404).json({ error: "Server not found" });
      return;
    }
    const [tools, findings, score_detail] = await Promise.all([
      db.getToolsForServer(server.id),
      db.getFindingsForServer(server.id),
      db.getLatestScoreForServer(server.id),
    ]);
    res.json({ data: { ...server, tools, findings, score_detail } });
  } catch (err) {
    logger.error(err, "Server detail error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/servers/:slug/findings — Findings for a server
app.get(
  "/api/v1/servers/:slug/findings",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const { slug } = req.params;
    if (!slug || !isValidSlug(slug)) {
      res.status(400).json({ error: "Invalid server slug" });
      return;
    }
    try {
      const server = await db.findServerBySlug(slug);
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
  }
);

// ─── Compliance routes ────────────────────────────────────────────────────────
// Judge-confirmed compliance findings grouped by framework. Powers the
// Compliance tab on the server detail page. Only judge-confirmed rows ever
// reach this endpoint (the persistence layer drops anything else at write
// time), and LLM-only fields — `judge_rationale`, prompts, response text —
// are NEVER exposed publicly. Regulators can replay via the private
// `compliance_agent_runs` audit trail; the public surface is deliberately
// narrow so we don't accidentally leak LLM reasoning text that might contain
// server source code excerpts.

/** Redact LLM-derived narrative fields before returning over the wire. */
function publicComplianceRow(row: ComplianceFindingRecord): {
  id: string;
  framework: ComplianceFrameworkIdType;
  rule_id: string;
  category_control: string;
  severity: ComplianceFindingRecord["severity"];
  confidence: number;
  bundle_id: string;
  test_id: string;
  test_hypothesis: string;
  evidence_chain: ComplianceFindingRecord["evidence_chain"];
  remediation: string;
  created_at: Date;
} {
  return {
    id: row.id,
    framework: row.framework,
    rule_id: row.rule_id,
    category_control: row.category_control,
    severity: row.severity,
    confidence: row.confidence,
    bundle_id: row.bundle_id,
    test_id: row.test_id,
    test_hypothesis: row.test_hypothesis,
    evidence_chain: row.evidence_chain,
    remediation: row.remediation,
    created_at: row.created_at,
  };
}

// GET /api/v1/servers/:slug/compliance — All frameworks, grouped
//
// Response shape:
//   { data: {
//       eu_ai_act:   [ ...publicComplianceRow ],
//       mitre_atlas: [ ... ],
//       owasp_mcp:   [ ... ],
//       owasp_asi:   [ ... ],
//       cosai:       [ ... ],
//       maestro:     [ ... ],
//     },
//     meta: { total_findings, frameworks_with_findings, last_scan_at }
//   }
//
// Frameworks with zero findings are still included as empty arrays so the
// UI can distinguish "nothing found" from "not scanned".
app.get(
  "/api/v1/servers/:slug/compliance",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const { slug } = req.params;
    if (!slug || !isValidSlug(slug)) {
      res.status(400).json({ error: "Invalid server slug" });
      return;
    }
    try {
      const server = await db.findServerBySlug(slug);
      if (!server) {
        res.status(404).json({ error: "Server not found" });
        return;
      }
      const rows = await db.getComplianceFindingsForServer(server.id);
      const grouped: Record<ComplianceFrameworkIdType, ReturnType<typeof publicComplianceRow>[]> = {
        eu_ai_act: [],
        mitre_atlas: [],
        owasp_mcp: [],
        owasp_asi: [],
        cosai: [],
        maestro: [],
      };
      let lastScanAt: Date | null = null;
      for (const row of rows) {
        grouped[row.framework].push(publicComplianceRow(row));
        if (!lastScanAt || row.created_at > lastScanAt) {
          lastScanAt = row.created_at;
        }
      }
      const frameworksWithFindings = (
        Object.keys(grouped) as ComplianceFrameworkIdType[]
      ).filter((k) => grouped[k].length > 0).length;
      res.json({
        data: grouped,
        meta: {
          total_findings: rows.length,
          frameworks_with_findings: frameworksWithFindings,
          last_scan_at: lastScanAt,
        },
      });
    } catch (err) {
      logger.error(err, "Compliance findings error");
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// GET /api/v1/servers/:slug/compliance/:framework — Single framework
//
// Response shape:
//   { data: [ ...publicComplianceRow ],
//     meta: { framework, total_findings, last_scan_at } }
//
// Returns 400 on unknown framework id. Returns 200 with an empty `data`
// array when the server has no findings for that framework (so the UI can
// render a confident "no findings in this framework" state rather than
// showing an error).
app.get(
  "/api/v1/servers/:slug/compliance/:framework",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const { slug, framework } = req.params;
    if (!slug || !isValidSlug(slug)) {
      res.status(400).json({ error: "Invalid server slug" });
      return;
    }
    const parsedFramework = ComplianceFrameworkId.safeParse(framework);
    if (!parsedFramework.success) {
      res.status(400).json({
        error: "Invalid framework id",
        valid: ComplianceFrameworkId.options,
      });
      return;
    }
    try {
      const server = await db.findServerBySlug(slug);
      if (!server) {
        res.status(404).json({ error: "Server not found" });
        return;
      }
      const rows = await db.getComplianceFindingsForServer(
        server.id,
        parsedFramework.data
      );
      let lastScanAt: Date | null = null;
      for (const row of rows) {
        if (!lastScanAt || row.created_at > lastScanAt) {
          lastScanAt = row.created_at;
        }
      }
      res.json({
        data: rows.map(publicComplianceRow),
        meta: {
          framework: parsedFramework.data,
          total_findings: rows.length,
          last_scan_at: lastScanAt,
        },
      });
    } catch (err) {
      logger.error(err, "Compliance per-framework error");
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// GET /api/v1/servers/:slug/history — Score history
app.get(
  "/api/v1/servers/:slug/history",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const { slug } = req.params;
    if (!slug || !isValidSlug(slug)) {
      res.status(400).json({ error: "Invalid server slug" });
      return;
    }
    try {
      const server = await db.findServerBySlug(slug);
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
  }
);

// GET /api/v1/servers/:slug/risk-edges — Cross-server attack paths involving this server
app.get(
  "/api/v1/servers/:slug/risk-edges",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const { slug } = req.params;
    if (!slug || !isValidSlug(slug)) {
      res.status(400).json({ error: "Invalid server slug" });
      return;
    }
    try {
      const server = await db.findServerBySlug(slug);
      if (!server) {
        res.status(404).json({ error: "Server not found" });
        return;
      }
      const edges = await db.getRiskEdgesForServer(server.id);
      res.json({ data: edges });
    } catch (err) {
      logger.error(err, "Risk edges error");
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// GET /api/v1/servers/:slug/badge.svg — Dynamic SVG security badge
//
// Security notes:
// - Returns 200 with a grey "unknown" badge for missing slugs (not 404).
//   This matches shields.io convention and avoids leaking server existence
//   information via HTTP status codes in embedded badge contexts.
// - Content-Security-Policy: default-src 'none' prevents the SVG from loading
//   external resources or executing scripts when embedded inline in HTML.
// - ETag enables CDN/browser caching without serving stale scores indefinitely.
// - Stale scores (> 7 days) get a shorter cache TTL to encourage re-fetching.
app.get(
  "/api/v1/servers/:slug/badge.svg",
  rateLimitMiddleware(RATE_MAX_BADGE),
  async (req: Request, res: Response) => {
    const { slug } = req.params;

    // Set SVG-specific security headers before any response path
    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
    res.setHeader("X-Content-Type-Options", "nosniff");

    // Unknown or invalid slug → grey "unknown" badge (200 OK, not 404)
    // A 404 breaks the badge image in README embeds.
    if (!slug || !isValidSlug(slug)) {
      res.setHeader("Cache-Control", "public, max-age=300");
      res.status(200).send(createBadgeSvg("mcp sentinel", "unknown", "#999"));
      return;
    }

    try {
      const server = await db.findServerBySlug(slug);

      if (!server) {
        res.setHeader("Cache-Control", "public, max-age=300");
        res.status(200).send(createBadgeSvg("mcp sentinel", "not found", "#999"));
        return;
      }

      const score = server.latest_score;
      const lastScannedAt = (server as Record<string, unknown>)["last_scanned_at"];
      const isStale =
        !lastScannedAt ||
        Date.now() - new Date(lastScannedAt as string).getTime() > 7 * 24 * 60 * 60 * 1000;

      let valueLabel: string;
      let color: string;

      if (score === null) {
        valueLabel = "unscanned";
        color = "#999";
      } else {
        valueLabel = `${score}/100`;
        if (score >= 80) color = "#4c1";
        else if (score >= 60) color = "#dfb317";
        else if (score >= 40) color = "#fe7d37";
        else color = "#e05d44";
      }

      // Stale data: shorter cache so CDNs pick up updated scores sooner
      const maxAge = isStale ? 300 : 3600;
      const etag = `"${score ?? "unscanned"}-${isStale ? "stale" : "fresh"}"`;

      res.setHeader("Cache-Control", `public, max-age=${maxAge}, stale-while-revalidate=60`);
      res.setHeader("ETag", etag);
      res.setHeader("Vary", "Accept-Encoding");

      // Conditional GET — return 304 if client already has current version
      if (req.headers["if-none-match"] === etag) {
        res.status(304).end();
        return;
      }

      res.status(200).send(createBadgeSvg("mcp sentinel", valueLabel, color));
    } catch (err) {
      logger.error(err, "Badge error");
      // Error badge — short cache, don't propagate server errors to CDNs
      res.setHeader("Cache-Control", "no-store");
      res.status(200).send(createBadgeSvg("mcp sentinel", "error", "#999"));
    }
  }
);

// Fallback badge route — catches badge.svg requests that don't match the strict
// /api/v1/servers/:slug/badge.svg pattern. Express normalises path traversal before
// routing (e.g. /api/v1/servers/../etc/badge.svg → /api/v1/etc/badge.svg), so the
// fallback must match any URL that ends with /badge.svg, not just ones under /servers/.
// Returns a grey "unknown" badge (200) rather than 404 so that embedded badge images
// in README files don't appear broken and don't leak server-existence information.
app.get(
  /\/badge\.svg$/,
  rateLimitMiddleware(RATE_MAX_BADGE),
  (_req: Request, res: Response) => {
    res.setHeader("Content-Type", "image/svg+xml");
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "public, max-age=300");
    res.status(200).send(createBadgeSvg("mcp sentinel", "unknown", "#999"));
  }
);

// POST /api/v1/risk-matrix — Cross-server capability graph and attack path detection
//
// Accepts a set of server IDs (from the registry database) and returns a
// RiskMatrixReport describing dangerous capability combinations across them.
// This is the API surface for the Layer 5 cross-server analysis (P01–P12 patterns).
//
// The endpoint is POST (not GET) because the server ID set can be large and is
// logically a "query body", not a URL parameter.
//
// Security: POST endpoint, but still read-only (no DB writes). CORS allows only
// safe methods on GET/HEAD/OPTIONS — POST here is intentional and controlled.
const RiskMatrixRequestSchema = z.object({
  server_ids: z
    .array(z.string().uuid())
    .min(1, "At least one server_id is required")
    .max(100, "Maximum 100 server_ids per request"),
});

app.post(
  "/api/v1/risk-matrix",
  rateLimitMiddleware(),
  async (req: Request, res: Response) => {
    const parsed = RiskMatrixRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: "Invalid request body", issues: parsed.error.issues });
      return;
    }

    try {
      const servers = await db.getServersByIds(parsed.data.server_ids);
      if (servers.length === 0) {
        res.status(404).json({ error: "No servers found for the provided IDs" });
        return;
      }

      // Fetch tools for each server (needed for capability classification)
      const serverInputs = await Promise.all(
        servers.map(async (s: Server) => {
          const tools = await db.getToolsForServer(s.id);
          return {
            server_id: s.id,
            server_name: s.name,
            server_slug: s.slug ?? s.name,
            latest_score: s.latest_score,
            category: s.category,
            tools: tools.map((t) => ({
              name: t.name,
              description: t.description,
              capability_tags: (t as Record<string, unknown>)["capability_tags"] as string[] | undefined,
            })),
          };
        })
      );

      const analyzer = new RiskMatrixAnalyzer();
      const report = analyzer.analyze(serverInputs);

      res.json({ data: report });
    } catch (err) {
      logger.error(err, "Risk matrix error");
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

// GET /api/v1/ecosystem/stats — Aggregate ecosystem statistics
app.get("/api/v1/ecosystem/stats", rateLimitMiddleware(), async (_req: Request, res: Response) => {
  try {
    const stats = await db.getEcosystemStats();
    res.json({ data: stats });
  } catch (err) {
    logger.error(err, "Stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/v1/ecosystem/dedup-stats — Deduplication quality report
// Shows how well canonical identifiers (github_url, npm_package, pypi_package) are
// populated and how many servers are confirmed by multiple independent sources.
// Useful for operational monitoring of crawler data quality.
app.get("/api/v1/ecosystem/dedup-stats", rateLimitMiddleware(), async (_req: Request, res: Response) => {
  try {
    const stats = await db.getDedupStats();
    res.json({ data: stats });
  } catch (err) {
    logger.error(err, "Dedup stats error");
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET / — API root info
app.get("/", (_req: Request, res: Response) => {
  res.json({ name: "MCP Sentinel API", version: "1.0.0", docs: "/api/v1" });
});

// GET /health — Health check
// Note: Returns only status + uptime. Never expose OS version, memory, DB
// details, or env vars here (rule J4: Health Endpoint Information Disclosure).
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// ─── 404 Handler ──────────────────────────────────────────────────────────────
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found" });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
// Prevents Express from leaking stack traces in error responses (rule C6).
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  logger.error(err, "Unhandled error");
  res.status(500).json({ error: "Internal server error" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env["PORT"] ?? "3100", 10);

async function start() {
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

// Only auto-start when NOT imported by a test runner.
// Tests import `app` directly and drive it via supertest — no port binding needed.
// Only auto-start when NOT imported by a test runner.
// Tests import `app` directly and drive it via supertest — no port binding needed.
if (process.env["NODE_ENV"] !== "test") {
  start();
}

export { app };

// ─── Test helpers ─────────────────────────────────────────────────────────────
// Exported with a _test prefix so it is clearly not part of the public API.
// Call this in beforeEach to prevent rate-limit state from leaking between tests.
export function _resetRateLimiters(): void {
  rateLimitStore.clear();
}
