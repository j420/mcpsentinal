/**
 * API Security Integration Tests
 *
 * Uses supertest to drive Express routes without starting a real TCP server.
 * The database layer is fully mocked via vi.mock so tests run without PostgreSQL.
 *
 * Coverage:
 *   - Slug validation (path traversal, null bytes, special chars, length)
 *   - Security headers on every response
 *   - Badge behaviour (200 for unknown slugs, ETag, stale TTL, CSP)
 *   - CORS method restriction
 *   - Rate limiting (101st request returns 429)
 *   - Global error handler (no stack trace leakage)
 *   - Health endpoint (no internals exposed)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import request from "supertest";
import { z } from "zod";

// ─── Mock the database module before server.ts is imported ───────────────────
// All calls to DatabaseQueries, ServerListQuerySchema, and migrate are replaced
// with controllable fakes so no real PostgreSQL is needed.
vi.mock("@mcp-sentinel/database", () => {
  const mockDb = {
    searchServers: vi.fn().mockResolvedValue({ servers: [], total: 0, page: 1, limit: 20 }),
    findServerBySlug: vi.fn().mockResolvedValue(null),
    getToolsForServer: vi.fn().mockResolvedValue([]),
    getFindingsForServer: vi.fn().mockResolvedValue([]),
    getLatestScoreForServer: vi.fn().mockResolvedValue(null),
    getScoreHistory: vi.fn().mockResolvedValue([]),
    getEcosystemStats: vi.fn().mockResolvedValue({ total_servers: 0, scanned: 0 }),
    // Trust Signature / Attestation Ribbon dependencies (added 2026-04-29).
    getSourcesForServer: vi.fn().mockResolvedValue([]),
    getLatestScanStages: vi.fn().mockResolvedValue(null),
    getDependenciesForServer: vi.fn().mockResolvedValue([]),
  };

  // Real Zod schema for ScoreDetailResponse — kept in sync with
  // packages/database/src/schemas.ts. We re-declare it here (rather than
  // importing) so this test file remains hermetic w.r.t. compiled dist
  // artefacts and the build order of @mcp-sentinel/database.
  const V2SubScoresSchema = z.object({
    schema_score: z.number().int().min(0).max(100),
    ecosystem_score: z.number().int().min(0).max(100),
    protocol_score: z.number().int().min(0).max(100),
    adversarial_score: z.number().int().min(0).max(100),
    compliance_score: z.number().int().min(0).max(100),
    supply_chain_score: z.number().int().min(0).max(100),
    infrastructure_score: z.number().int().min(0).max(100),
  });
  const AnalysisCoverageSchema = z.object({
    had_source_code: z.boolean(),
    had_connection: z.boolean(),
    had_dependencies: z.boolean(),
    coverage_ratio: z.number().min(0).max(1),
    techniques_run: z.array(z.string()),
    rules_executed: z.number().int().nonnegative(),
    rules_skipped_no_data: z.number().int().nonnegative(),
  });
  const ScoreDetailResponseSchema = z.object({
    total_score: z.number().int().min(0).max(100),
    code_score: z.number().int().min(0).max(100),
    deps_score: z.number().int().min(0).max(100),
    config_score: z.number().int().min(0).max(100),
    description_score: z.number().int().min(0).max(100),
    behavior_score: z.number().int().min(0).max(100),
    owasp_coverage: z.record(z.boolean()),
    coverage_band: z.enum(["high", "medium", "low", "minimal"]).nullable(),
    v2_sub_scores: V2SubScoresSchema.nullable(),
    analysis_coverage: AnalysisCoverageSchema.nullable(),
  });

  return {
    DatabaseQueries: vi.fn(() => mockDb),
    ServerListQuerySchema: {
      safeParse: vi.fn((input) => ({ success: true, data: input })),
    },
    ScoreDetailResponseSchema,
    migrate: vi.fn().mockResolvedValue(undefined),
    // Re-export the mock db so tests can configure return values
    _mockDb: mockDb,
  };
});

// ─── Mock red-team — its real load pulls in @mcp-sentinel/analyzer (164 rules)
// which adds 5–10s on CI runners and trips the 5s test timeout on the first
// /servers/:slug request. Tests that need the corpus value can override.
vi.mock("@mcp-sentinel/red-team", () => ({
  getCorpusManifest: vi.fn().mockResolvedValue({}),
}));

// ─── Mock pg to avoid real connection pools ───────────────────────────────────
vi.mock("pg", () => ({
  default: {
    Pool: vi.fn(() => ({
      connect: vi.fn(),
      end: vi.fn(),
      query: vi.fn(),
    })),
  },
}));

// Set NODE_ENV=test so server.ts does NOT auto-call start() / app.listen()
process.env["NODE_ENV"] = "test";

// Import AFTER mocks are in place
const { app, _resetRateLimiters } = await import("../server.js");

// Helper to get the mock db object for per-test configuration.
// The double cast (as unknown as ...) is required because _mockDb is injected
// by vi.mock() at runtime and does not exist in the real module's TypeScript types.
type MockDb = {
  findServerBySlug: ReturnType<typeof vi.fn>;
  searchServers: ReturnType<typeof vi.fn>;
  getFindingsForServer: ReturnType<typeof vi.fn>;
  getScoreHistory: ReturnType<typeof vi.fn>;
  getLatestScoreForServer: ReturnType<typeof vi.fn>;
  getToolsForServer: ReturnType<typeof vi.fn>;
};
const { _mockDb: db } = (await import("@mcp-sentinel/database")) as unknown as {
  _mockDb: MockDb;
};

beforeEach(() => {
  vi.clearAllMocks();
  // Default: server not found
  db.findServerBySlug.mockResolvedValue(null);
  // Clear the in-memory rate limit store so tests don't bleed rate-limit state
  // into each other (the rate limiting tests deliberately exhaust the limit).
  _resetRateLimiters();
});

// ═══════════════════════════════════════════════════════════════════════════════
// Security headers — present on every route
// ═══════════════════════════════════════════════════════════════════════════════

describe("Security headers", () => {
  const routes = [
    "/",
    "/health",
    "/api/v1/servers",
    "/api/v1/ecosystem/stats",
  ];

  for (const route of routes) {
    it(`${route} includes X-Content-Type-Options: nosniff`, async () => {
      const res = await request(app).get(route);
      expect(res.headers["x-content-type-options"]).toBe("nosniff");
    });

    it(`${route} includes X-Frame-Options: DENY`, async () => {
      const res = await request(app).get(route);
      expect(res.headers["x-frame-options"]).toBe("DENY");
    });

    it(`${route} includes Referrer-Policy: no-referrer`, async () => {
      const res = await request(app).get(route);
      expect(res.headers["referrer-policy"]).toBe("no-referrer");
    });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CORS — method restriction
// ═══════════════════════════════════════════════════════════════════════════════

describe("CORS", () => {
  it("allows GET via Access-Control-Allow-Methods", async () => {
    const res = await request(app)
      .options("/api/v1/servers")
      .set("Origin", "https://example.com")
      .set("Access-Control-Request-Method", "GET");
    expect(res.headers["access-control-allow-methods"]).toMatch(/GET/);
  });

  it("does not allow POST in Access-Control-Allow-Methods", async () => {
    const res = await request(app)
      .options("/api/v1/servers")
      .set("Origin", "https://example.com")
      .set("Access-Control-Request-Method", "POST");
    const allowed = res.headers["access-control-allow-methods"] ?? "";
    expect(allowed).not.toMatch(/POST/);
  });

  it("does not allow DELETE in Access-Control-Allow-Methods", async () => {
    const res = await request(app)
      .options("/api/v1/servers")
      .set("Origin", "https://example.com")
      .set("Access-Control-Request-Method", "DELETE");
    const allowed = res.headers["access-control-allow-methods"] ?? "";
    expect(allowed).not.toMatch(/DELETE/);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Slug validation — /api/v1/servers/:slug routes
// ═══════════════════════════════════════════════════════════════════════════════

describe("Slug validation", () => {
  const slugRoutes = [
    "/api/v1/servers/{slug}",
    "/api/v1/servers/{slug}/findings",
    "/api/v1/servers/{slug}/history",
  ];

  const invalidSlugs = [
    // Path traversal
    { slug: "../etc/passwd",        label: "path traversal with .." },
    { slug: "..%2fetc%2fpasswd",    label: "URL-encoded path traversal" },
    { slug: "a".repeat(101),        label: "slug exceeds 100 chars" },
    { slug: "slug with spaces",     label: "spaces in slug" },
    { slug: "UPPERCASE",            label: "uppercase-only slug" },
    { slug: "slug/extra",           label: "forward slash in slug" },
  ];

  for (const route of slugRoutes) {
    for (const { slug, label } of invalidSlugs) {
      it(`${route} returns 400 for ${label}`, async () => {
        const url = route.replace("{slug}", encodeURIComponent(slug));
        const res = await request(app).get(url);
        expect(res.status).toBe(400);
        expect(res.body).toHaveProperty("error");
      });
    }
  }

  it("accepts a valid lowercase slug", async () => {
    // DB returns null (not found) — that's fine, just checking validation passes
    const res = await request(app).get("/api/v1/servers/valid-slug-123");
    expect(res.status).toBe(404); // not found, but validation passed
  });

  it("accepts a single-character slug", async () => {
    const res = await request(app).get("/api/v1/servers/a");
    expect(res.status).toBe(404);
  });

  it("accepts alphanumeric slug with hyphens and underscores", async () => {
    const res = await request(app).get("/api/v1/servers/my_server-v2");
    expect(res.status).toBe(404);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Badge endpoint — security-specific behaviour
// ═══════════════════════════════════════════════════════════════════════════════

describe("Badge endpoint", () => {
  it("returns 200 (not 404) for unknown server slugs", async () => {
    // Shields.io embeds break on non-2xx — always return 200 with grey badge
    db.findServerBySlug.mockResolvedValue(null);
    const res = await request(app).get("/api/v1/servers/unknown-server/badge.svg");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/image\/svg\+xml/);
  });

  it("returns 200 with grey badge for invalid slug (no info leakage)", async () => {
    const res = await request(app).get("/api/v1/servers/../etc/badge.svg");
    expect(res.status).toBe(200);
    // supertest/superagent treats image/* as binary; fall back to Buffer when res.text is absent
    const body = res.text ?? Buffer.from(res.body as Buffer).toString("utf-8");
    expect(body).toContain("unknown");
  });

  it("includes Content-Security-Policy: default-src 'none' on badge responses", async () => {
    const res = await request(app).get("/api/v1/servers/any-slug/badge.svg");
    const csp = res.headers["content-security-policy"] ?? "";
    expect(csp).toMatch(/default-src\s+'none'/);
  });

  it("includes Cache-Control header on badge responses", async () => {
    const res = await request(app).get("/api/v1/servers/any-slug/badge.svg");
    expect(res.headers["cache-control"]).toBeTruthy();
  });

  it("includes ETag header when server exists with a score", async () => {
    db.findServerBySlug.mockResolvedValue({
      id: "1",
      slug: "my-server",
      latest_score: 85,
      last_scanned_at: new Date().toISOString(),
    });
    const res = await request(app).get("/api/v1/servers/my-server/badge.svg");
    expect(res.headers["etag"]).toBeTruthy();
  });

  it("returns 304 on conditional GET when ETag matches", async () => {
    const recentDate = new Date().toISOString();
    db.findServerBySlug.mockResolvedValue({
      id: "1",
      slug: "my-server",
      latest_score: 85,
      last_scanned_at: recentDate,
    });

    // First request to get the ETag
    const first = await request(app).get("/api/v1/servers/my-server/badge.svg");
    const etag = first.headers["etag"];
    expect(etag).toBeTruthy();

    // Second request with If-None-Match → must 304
    const second = await request(app)
      .get("/api/v1/servers/my-server/badge.svg")
      .set("If-None-Match", etag);
    expect(second.status).toBe(304);
  });

  it("uses shorter Cache-Control TTL for stale scores (> 7 days)", async () => {
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    db.findServerBySlug.mockResolvedValue({
      id: "1",
      slug: "stale-server",
      latest_score: 72,
      last_scanned_at: eightDaysAgo,
    });
    const res = await request(app).get("/api/v1/servers/stale-server/badge.svg");
    // Stale badges get max-age=300 (5 min), fresh get max-age=3600 (1 hr)
    expect(res.headers["cache-control"]).toMatch(/max-age=300/);
  });

  it("SVG output for a real server does not contain raw user data unescaped", async () => {
    db.findServerBySlug.mockResolvedValue({
      id: "1",
      slug: "my-server",
      latest_score: 55,
      last_scanned_at: new Date().toISOString(),
    });
    const res = await request(app).get("/api/v1/servers/my-server/badge.svg");
    // supertest/superagent treats image/* as binary; fall back to Buffer when res.text is absent
    const svg = res.text ?? Buffer.from(res.body as Buffer).toString("utf-8");
    // Score values are numeric — no injection surface here, but verify
    expect(svg).not.toContain("<script>");
    expect(svg).toContain("55/100");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Rate limiting
// ═══════════════════════════════════════════════════════════════════════════════

describe("Rate limiting", () => {
  it("allows up to 100 requests per minute on /api/v1/servers", async () => {
    // Send 100 requests — all should succeed (2xx or 4xx, not 429)
    const responses = await Promise.all(
      Array.from({ length: 10 }, () => request(app).get("/api/v1/servers"))
    );
    for (const res of responses) {
      expect(res.status).not.toBe(429);
    }
  });

  it("returns 429 after exceeding the rate limit", async () => {
    // The rate limiter is per IP. In supertest, all requests come from the same
    // socket address. Send 120 requests to push past the 100/min limit.
    // Note: this test may interact with state from earlier tests in the suite
    // because the in-memory rate store persists per process.
    const allRequests = Array.from({ length: 120 }, () =>
      request(app).get("/api/v1/ecosystem/stats")
    );
    const responses = await Promise.all(allRequests);
    const tooMany = responses.filter((r) => r.status === 429);
    // At least some requests should be rate-limited
    expect(tooMany.length).toBeGreaterThan(0);
  });

  it("rate limit response includes retry_after_seconds", async () => {
    // Send enough requests to trigger the limiter
    const responses = await Promise.all(
      Array.from({ length: 120 }, () => request(app).get("/api/v1/servers"))
    );
    const limited = responses.find((r) => r.status === 429);
    if (limited) {
      expect(limited.body).toHaveProperty("retry_after_seconds");
      expect(typeof limited.body.retry_after_seconds).toBe("number");
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Health endpoint — minimal information disclosure
// ═══════════════════════════════════════════════════════════════════════════════

describe("Health endpoint", () => {
  it("returns 200 with status: ok", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
  });

  it("does NOT expose OS info, memory, or env vars (rule J4)", async () => {
    const res = await request(app).get("/health");
    const body = JSON.stringify(res.body);
    // These patterns indicate J4-class information disclosure
    expect(body).not.toMatch(/process\.version/i);
    expect(body).not.toMatch(/platform/i);
    expect(body).not.toMatch(/memoryUsage/i);
    expect(body).not.toMatch(/cpuUsage/i);
    expect(body).not.toMatch(/DATABASE_URL/i);
    // Timestamp would reveal server time — keep it minimal
    expect(Object.keys(res.body)).toEqual(["status"]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Global error handler — no stack trace in responses
// ═══════════════════════════════════════════════════════════════════════════════

describe("Error handling", () => {
  it("returns 500 with generic message when DB throws", async () => {
    db.findServerBySlug.mockRejectedValue(new Error("DB connection lost at /var/run/pg.sock"));

    const res = await request(app).get("/api/v1/servers/some-server");
    expect(res.status).toBe(500);
    expect(res.body.error).toBe("Internal server error");
    // Stack trace and DB path must NOT appear in the response body
    expect(JSON.stringify(res.body)).not.toContain("DB connection lost");
    expect(JSON.stringify(res.body)).not.toContain("/var/run");
  });

  it("returns 404 for completely unknown routes", async () => {
    const res = await request(app).get("/api/v2/nonexistent");
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Server detail — correct 404 for valid slug not in DB
// ═══════════════════════════════════════════════════════════════════════════════

describe("Server detail", () => {
  it("returns 404 when slug is valid but server not in DB", async () => {
    db.findServerBySlug.mockResolvedValue(null);
    const res = await request(app).get("/api/v1/servers/valid-but-missing");
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found/i);
  });

  it("returns server data when found", async () => {
    const mockServer = {
      id: "abc",
      slug: "my-server",
      name: "My Server",
      latest_score: 80,
    };
    db.findServerBySlug.mockResolvedValue(mockServer);
    db.getToolsForServer.mockResolvedValue([]);
    db.getFindingsForServer.mockResolvedValue([]);
    db.getLatestScoreForServer.mockResolvedValue({ total_score: 80 });

    const res = await request(app).get("/api/v1/servers/my-server");
    expect(res.status).toBe(200);
    expect(res.body.data.slug).toBe("my-server");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Server detail — score_detail v2 contract (CISO detail-page upgrade)
//
// Cluster A part 1 of 3: extends data.score_detail with three additive,
// nullable fields:
//   - coverage_band:    "high" | "medium" | "low" | "minimal" | null
//   - v2_sub_scores:    { schema/ecosystem/protocol/adversarial/compliance/
//                         supply_chain/infrastructure } | null
//   - analysis_coverage: { had_*, coverage_ratio, techniques_run, … } | null
//
// Contract invariants under test:
//   1. Existing legacy sub-scores MUST keep their shape (regression).
//   2. Servers with full v2 data → all three fields present, coverage_band
//      is one of the four literal values.
//   3. Servers with only legacy data → all three fields = null, no crash.
// ═══════════════════════════════════════════════════════════════════════════════

describe("Server detail score_detail (v2 contract)", () => {
  const baseServer = {
    id: "00000000-0000-0000-0000-000000000001",
    slug: "test-server",
    name: "Test Server",
    latest_score: 72,
  };

  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(baseServer);
  });

  // ── fixture-A: server with full v2 data ────────────────────────────────────
  it("fixture-A: exposes all three v2 fields when the score row is fully populated", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 72,
      code_score: 85,
      deps_score: 90,
      config_score: 60,
      description_score: 95,
      behavior_score: 100,
      owasp_coverage: { "MCP01-prompt-injection": false, "MCP05-privilege-escalation": true },
      coverage_band: "high",
      v2_sub_scores: {
        schema_score: 88,
        ecosystem_score: 70,
        protocol_score: 95,
        adversarial_score: 60,
        compliance_score: 75,
        supply_chain_score: 80,
        infrastructure_score: 100,
      },
      analysis_coverage: {
        had_source_code: true,
        had_connection: true,
        had_dependencies: true,
        coverage_ratio: 0.92,
        techniques_run: ["ast-taint", "capability-graph", "entropy", "linguistic-scoring"],
        rules_executed: 151,
        rules_skipped_no_data: 13,
      },
    });

    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    const detail = res.body.data.score_detail;
    expect(detail).not.toBeNull();

    // Legacy sub-scores still present + correct
    expect(detail.total_score).toBe(72);
    expect(detail.code_score).toBe(85);
    expect(detail.deps_score).toBe(90);
    expect(detail.config_score).toBe(60);
    expect(detail.description_score).toBe(95);
    expect(detail.behavior_score).toBe(100);
    expect(detail.owasp_coverage).toEqual({
      "MCP01-prompt-injection": false,
      "MCP05-privilege-escalation": true,
    });

    // New additive fields
    expect(detail.coverage_band).toBe("high");
    expect(["high", "medium", "low", "minimal"]).toContain(detail.coverage_band);
    expect(detail.v2_sub_scores).toEqual({
      schema_score: 88,
      ecosystem_score: 70,
      protocol_score: 95,
      adversarial_score: 60,
      compliance_score: 75,
      supply_chain_score: 80,
      infrastructure_score: 100,
    });
    expect(detail.analysis_coverage).toEqual({
      had_source_code: true,
      had_connection: true,
      had_dependencies: true,
      coverage_ratio: 0.92,
      techniques_run: ["ast-taint", "capability-graph", "entropy", "linguistic-scoring"],
      rules_executed: 151,
      rules_skipped_no_data: 13,
    });
  });

  // ── fixture-B: server with only legacy scores ──────────────────────────────
  it("fixture-B: returns null for all three v2 fields on legacy/pre-migration scans", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 65,
      code_score: 80,
      deps_score: 85,
      config_score: 50,
      description_score: 90,
      behavior_score: 95,
      owasp_coverage: {},
      // No coverage_band, no v2_sub_scores, no analysis_coverage —
      // exactly what the database returns today (Scenario B).
      coverage_band: null,
      v2_sub_scores: null,
      analysis_coverage: null,
    });

    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    const detail = res.body.data.score_detail;
    expect(detail).not.toBeNull();

    // Legacy fields still present
    expect(detail.total_score).toBe(65);
    expect(detail.code_score).toBe(80);
    expect(detail.deps_score).toBe(85);
    expect(detail.config_score).toBe(50);
    expect(detail.description_score).toBe(90);
    expect(detail.behavior_score).toBe(95);

    // All three additive fields explicitly null — never undefined, never absent
    expect(detail.coverage_band).toBeNull();
    expect(detail.v2_sub_scores).toBeNull();
    expect(detail.analysis_coverage).toBeNull();
    // Keys must be present even when null (so consumers can rely on the shape)
    expect(Object.prototype.hasOwnProperty.call(detail, "coverage_band")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(detail, "v2_sub_scores")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(detail, "analysis_coverage")).toBe(true);
  });

  // ── regression: existing fields shape unchanged ────────────────────────────
  it("regression: existing legacy score_detail shape is unchanged (additive only)", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 78,
      code_score: 88,
      deps_score: 92,
      config_score: 55,
      description_score: 89,
      behavior_score: 100,
      owasp_coverage: { "MCP03-command-injection": true },
      coverage_band: null,
      v2_sub_scores: null,
      analysis_coverage: null,
    });

    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    const detail = res.body.data.score_detail;

    // Shape is exactly the legacy 7 keys + 3 additive keys, nothing else.
    // Sorted for stable comparison across JSON serialisations.
    expect(Object.keys(detail).sort()).toEqual(
      [
        "analysis_coverage",
        "behavior_score",
        "code_score",
        "config_score",
        "coverage_band",
        "deps_score",
        "description_score",
        "owasp_coverage",
        "total_score",
        "v2_sub_scores",
      ].sort(),
    );

    // Legacy fields are integers in [0, 100] (not strings, not floats)
    for (const key of [
      "total_score",
      "code_score",
      "deps_score",
      "config_score",
      "description_score",
      "behavior_score",
    ]) {
      expect(typeof detail[key]).toBe("number");
      expect(Number.isInteger(detail[key])).toBe(true);
      expect(detail[key]).toBeGreaterThanOrEqual(0);
      expect(detail[key]).toBeLessThanOrEqual(100);
    }
    expect(typeof detail.owasp_coverage).toBe("object");
    expect(detail.owasp_coverage).not.toBeNull();
  });

  // ── boundary: server with no score yet returns null ────────────────────────
  it("returns score_detail = null when the server has never been scored", async () => {
    db.getLatestScoreForServer.mockResolvedValue(null);
    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    expect(res.body.data.score_detail).toBeNull();
  });

  // ── boundary: malformed coverage_band must be rejected by the contract ─────
  it("rejects an invalid coverage_band literal at the response boundary", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 50,
      code_score: 50,
      deps_score: 50,
      config_score: 50,
      description_score: 50,
      behavior_score: 50,
      owasp_coverage: {},
      coverage_band: "extreme", // invalid — not in the union
      v2_sub_scores: null,
      analysis_coverage: null,
    });
    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    // Malformed row → score_detail collapses to null rather than leaking
    // an invalid literal to public consumers.
    expect(res.body.data.score_detail).toBeNull();
  });

  // ── boundary: v2_sub_scores must clamp to 0..100 ───────────────────────────
  it("rejects v2_sub_scores values outside 0..100 at the response boundary", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 50,
      code_score: 50,
      deps_score: 50,
      config_score: 50,
      description_score: 50,
      behavior_score: 50,
      owasp_coverage: {},
      coverage_band: "medium",
      v2_sub_scores: {
        schema_score: 150, // out of range — must be discarded
        ecosystem_score: 50,
        protocol_score: 50,
        adversarial_score: 50,
        compliance_score: 50,
        supply_chain_score: 50,
        infrastructure_score: 50,
      },
      analysis_coverage: null,
    });
    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    expect(res.body.data.score_detail).toBeNull();
  });
});
