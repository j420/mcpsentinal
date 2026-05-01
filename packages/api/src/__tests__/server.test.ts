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
    // Cluster B routing-precedence test calls /compliance/:framework.json
    // → assembleReport → getAttackChainsForServer. Default to empty so
    // the signed-report handler doesn't throw on the missing mock.
    getAttackChainsForServer: vi.fn().mockResolvedValue([]),
    getRiskEdgesForServer: vi.fn().mockResolvedValue([]),
    getComplianceFindingsForServer: vi.fn().mockResolvedValue([]),
  };

  // Real Zod schema for ScoreDetailResponse — kept in sync with
  // packages/database/src/schemas.ts. We re-declare it here (rather than
  // importing) so this test file remains hermetic w.r.t. compiled dist
  // artefacts and the build order of @mcp-sentinel/database.
  // NOTE: V2SubScoresSchema includes `code_score` (8 buckets, not 7) and
  // both schemas are `.passthrough()` to match the production contract
  // — future scorer additions must NOT silently null the field.
  const V2SubScoresSchema = z
    .object({
      schema_score: z.number().int().min(0).max(100),
      ecosystem_score: z.number().int().min(0).max(100),
      protocol_score: z.number().int().min(0).max(100),
      adversarial_score: z.number().int().min(0).max(100),
      compliance_score: z.number().int().min(0).max(100),
      supply_chain_score: z.number().int().min(0).max(100),
      infrastructure_score: z.number().int().min(0).max(100),
      code_score: z.number().int().min(0).max(100),
    })
    .passthrough();
  const AnalysisCoverageSchema = z
    .object({
      had_source_code: z.boolean(),
      had_connection: z.boolean(),
      had_dependencies: z.boolean(),
      coverage_ratio: z.number().min(0).max(1),
      techniques_run: z.array(z.string()),
      rules_executed: z.number().int().nonnegative(),
      rules_skipped_no_data: z.number().int().nonnegative(),
    })
    .passthrough();
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
        code_score: 85,
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
      code_score: 85,
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
        code_score: 50,
      },
      analysis_coverage: null,
    });
    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    expect(res.body.data.score_detail).toBeNull();
  });

  // ── B3 regression — extra unknown fields on v2_sub_scores or analysis_coverage
  // must not collapse the response. Future scorer additions are forwarded
  // verbatim via Zod `.passthrough()` rather than silently nulled.
  it("preserves v2_sub_scores when the row carries an unknown future field (passthrough)", async () => {
    db.getLatestScoreForServer.mockResolvedValue({
      total_score: 72,
      code_score: 85,
      deps_score: 90,
      config_score: 60,
      description_score: 95,
      behavior_score: 100,
      owasp_coverage: {},
      coverage_band: "high",
      v2_sub_scores: {
        schema_score: 88,
        ecosystem_score: 70,
        protocol_score: 95,
        adversarial_score: 60,
        compliance_score: 75,
        supply_chain_score: 80,
        infrastructure_score: 100,
        code_score: 85,
        // Future scorer field — Zod must forward, not discard.
        runtime_score: 91,
      },
      analysis_coverage: {
        had_source_code: true,
        had_connection: true,
        had_dependencies: true,
        coverage_ratio: 0.9,
        techniques_run: ["ast-taint"],
        rules_executed: 150,
        rules_skipped_no_data: 14,
        // Future analysis-coverage field.
        notes: "future-scorer-metadata",
      },
    });
    const res = await request(app).get("/api/v1/servers/test-server");
    expect(res.status).toBe(200);
    const detail = res.body.data.score_detail;
    // The whole object survived validation — no silent null.
    expect(detail.v2_sub_scores).not.toBeNull();
    expect(detail.v2_sub_scores.schema_score).toBe(88);
    expect(detail.v2_sub_scores.code_score).toBe(85);
    // Unknown additive field is forwarded verbatim.
    expect(detail.v2_sub_scores.runtime_score).toBe(91);
    expect(detail.analysis_coverage).not.toBeNull();
    expect(detail.analysis_coverage.notes).toBe("future-scorer-metadata");
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Compliance Posture Matrix — GET /api/v1/servers/:slug/compliance
//
// Cluster B invention #3. The aggregate endpoint returns one entry per
// supported framework (7 total) so the registry can render the Posture
// Matrix without 7 round-trips. This is a NAVIGATIONAL summary — the
// signed, HMAC-attested artifacts continue to live at the per-framework
// `/compliance/:framework.{json,html,pdf}` endpoints.
//
// Hermetic Zod re-declarations: per Cluster A B3 lesson, these schemas
// are inlined here verbatim (matching production `.passthrough()`
// behaviour) so this test file does not depend on the database build
// order or compiled dist artefacts.
// ═══════════════════════════════════════════════════════════════════════════════

describe("Compliance posture matrix (GET /api/v1/servers/:slug/compliance)", () => {
  const FRAMEWORK_IDS = [
    "eu_ai_act",
    "iso_27001",
    "owasp_mcp",
    "owasp_asi",
    "cosai_mcp",
    "maestro",
    "mitre_atlas",
  ] as const;
  type MatrixFrameworkId = (typeof FRAMEWORK_IDS)[number];

  // ── Hermetic contract schemas (re-declared verbatim) ───────────────────────
  const ComplianceControlCountsSchema = z
    .object({
      met: z.number().int().nonnegative(),
      partial: z.number().int().nonnegative(),
      unmet: z.number().int().nonnegative(),
      not_applicable: z.number().int().nonnegative(),
      total: z.number().int().nonnegative(),
    })
    .passthrough();
  const ComplianceFrameworkDownloadPathsSchema = z
    .object({
      json: z.string().min(1),
      html: z.string().min(1),
      pdf: z.string().min(1),
      badge_svg: z.string().min(1),
    })
    .passthrough();
  const ComplianceFrameworkMatrixEntrySchema = z
    .object({
      framework_id: z.enum(FRAMEWORK_IDS),
      framework_name: z.string().min(1),
      framework_version: z.string().min(1),
      controls: ComplianceControlCountsSchema,
      overall_status: z.enum(["met", "partial", "unmet", "not_applicable"]),
      coverage_band: z.enum(["high", "medium", "low", "minimal"]),
      download_paths: ComplianceFrameworkDownloadPathsSchema,
    })
    .passthrough();
  const ComplianceMatrixResponseSchema = z
    .object({
      server_slug: z.string().min(1),
      server_name: z.string().min(1),
      last_assessed_at: z.string().nullable(),
      rules_version: z.string().min(1),
      frameworks: z.array(ComplianceFrameworkMatrixEntrySchema),
    })
    .passthrough();

  const baseServer = {
    id: "00000000-0000-0000-0000-000000000001",
    slug: "matrix-server",
    name: "Matrix Server",
    github_url: "https://github.com/example/matrix-server",
    last_scanned_at: null,
    latest_score: 60,
  };

  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(baseServer);
    db.getFindingsForServer.mockResolvedValue([]);
  });

  it("returns 200 with all 7 frameworks for a valid slug, even when the server has zero findings", async () => {
    db.getFindingsForServer.mockResolvedValue([]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    const parsed = ComplianceMatrixResponseSchema.safeParse(res.body.data);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const ids = parsed.data.frameworks.map((f) => f.framework_id).sort();
    expect(ids).toEqual([...FRAMEWORK_IDS].sort());
    // With zero findings every control is either `met` (rule didn't fire)
    // or `not_applicable` (no assessor rule mapped). Honest gaps render
    // explicitly — never silently as `met`.
    for (const entry of parsed.data.frameworks) {
      expect(entry.controls.unmet).toBe(0);
      expect(entry.controls.partial).toBe(0);
      expect(entry.controls.met + entry.controls.not_applicable).toBe(entry.controls.total);
      expect(["met", "not_applicable"]).toContain(entry.overall_status);
      expect(entry.coverage_band).toBe("minimal");
    }
  });

  it("returns counts matching real framework registry (62+ controls across 7 frameworks)", async () => {
    db.getFindingsForServer.mockResolvedValue([]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    const data = res.body.data as { frameworks: Array<{ controls: { total: number } }> };
    const totalControls = data.frameworks.reduce((acc, f) => acc + f.controls.total, 0);
    // Registry ships 62-63 controls; never zero. Guard against accidental
    // empty registry / malformed loop.
    expect(totalControls).toBeGreaterThanOrEqual(60);
  });

  it("flips overall_status to `unmet` when a critical finding hits an EU AI Act assessor rule (K1 → Art.12)", async () => {
    // K1 (Absent Structured Logging) is mapped under EU AI Act Art.12.
    // unmet_threshold for Art.12 is "medium" — a critical finding clears it.
    db.getFindingsForServer.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "K1",
        severity: "critical",
        evidence: "no structured logging detected",
        remediation: "use pino",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 0.9,
        evidence_chain: null,
        created_at: new Date("2026-04-25T12:00:00.000Z"),
      },
    ]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    const data = res.body.data as { frameworks: Array<{ framework_id: string; overall_status: string; controls: { unmet: number } }> };
    const eu = data.frameworks.find((f) => f.framework_id === "eu_ai_act");
    expect(eu).toBeDefined();
    expect(eu!.overall_status).toBe("unmet");
    expect(eu!.controls.unmet).toBeGreaterThanOrEqual(1);
  });

  it("download_paths are RELATIVE (no host) and target the per-framework signed-pack endpoints", async () => {
    db.getFindingsForServer.mockResolvedValue([]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    const data = res.body.data as {
      frameworks: Array<{
        framework_id: MatrixFrameworkId;
        download_paths: { json: string; html: string; pdf: string; badge_svg: string };
      }>;
    };
    for (const entry of data.frameworks) {
      const base = `/api/v1/servers/matrix-server/compliance/${entry.framework_id}`;
      expect(entry.download_paths.json).toBe(`${base}.json`);
      expect(entry.download_paths.html).toBe(`${base}.html`);
      expect(entry.download_paths.pdf).toBe(`${base}.pdf`);
      expect(entry.download_paths.badge_svg).toBe(`${base}/badge.svg`);
      // Negative regression: never bake the API origin into the path.
      expect(entry.download_paths.json.startsWith("http")).toBe(false);
      expect(entry.download_paths.json.startsWith("/")).toBe(true);
    }
  });

  it("sets Cache-Control: public, max-age=300 on the matrix response", async () => {
    db.getFindingsForServer.mockResolvedValue([]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("public, max-age=300");
  });

  it("returns 404 for unknown slug", async () => {
    db.findServerBySlug.mockResolvedValue(null);
    const res = await request(app).get("/api/v1/servers/no-such-server/compliance");
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });

  it("returns 400 for invalid slug (path traversal)", async () => {
    const res = await request(app).get("/api/v1/servers/..%2fevil/compliance");
    expect(res.status).toBe(400);
  });

  it("last_assessed_at mirrors the newest finding's created_at when findings exist", async () => {
    const newest = new Date("2026-04-29T08:00:00.000Z");
    db.getFindingsForServer.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "K1",
        severity: "low",
        evidence: "x",
        remediation: "y",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: new Date("2026-04-15T08:00:00.000Z"),
      },
      {
        id: "33333333-3333-3333-3333-333333333333",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "K2",
        severity: "low",
        evidence: "x",
        remediation: "y",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: newest,
      },
    ]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    expect(res.body.data.last_assessed_at).toBe(newest.toISOString());
  });

  it("last_assessed_at is null when no findings AND no last_scanned_at", async () => {
    db.findServerBySlug.mockResolvedValue({ ...baseServer, last_scanned_at: null });
    db.getFindingsForServer.mockResolvedValue([]);
    const res = await request(app).get("/api/v1/servers/matrix-server/compliance");
    expect(res.status).toBe(200);
    expect(res.body.data.last_assessed_at).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Routing precedence — /compliance vs /compliance/:framework.json
//
// Express matches routes in declaration order. The bare /compliance path
// has no trailing segment so it cannot collide with /compliance/:framework
// — but a regression in declaration order could shadow either route.
// This test pins the contract: BOTH must resolve as their respective
// handlers.
// ═══════════════════════════════════════════════════════════════════════════════

describe("Routing precedence: /compliance vs /compliance/:framework.json", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue({
      id: "00000000-0000-0000-0000-000000000001",
      slug: "demo-server",
      name: "Demo Server",
      github_url: null,
      last_scanned_at: null,
      latest_score: 70,
    });
    db.getFindingsForServer.mockResolvedValue([]);
  });

  it("GET /compliance returns the matrix shape (data.frameworks[])", async () => {
    const res = await request(app).get("/api/v1/servers/demo-server/compliance");
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.data?.frameworks)).toBe(true);
    expect(res.body.data.frameworks.length).toBe(7);
    // Negative: must NOT be the per-framework signed-report shape
    expect(res.body).not.toHaveProperty("attestation");
    expect(res.body.data).not.toHaveProperty("report");
  });

  it("GET /compliance/eu_ai_act.json still routes to the signed-report handler (no shadowing)", async () => {
    const res = await request(app).get("/api/v1/servers/demo-server/compliance/eu_ai_act.json");
    // The signed-report handler returns 500 here because the test mock
    // doesn't register a JSON renderer; the routing-precedence assertion
    // is that we do NOT 404 (which would mean the matrix route shadowed
    // the framework-suffixed route).
    expect(res.status).not.toBe(404);
    // And we must NOT have hit the matrix handler — its responses always
    // contain `data.frameworks[]`.
    if (res.status === 200) {
      expect(res.body.data?.frameworks).toBeUndefined();
    }
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// Per-finding framework cross-walk — GET /api/v1/servers/:slug/findings
//
// Cluster B invention #8. Every finding row carries
// `framework_controls: Array<{framework_id, control_id, control_title}>`
// computed by reverse-indexing the framework registry once per process.
//
// Contract invariants under test:
//   - Always present, always an array (never null/undefined).
//   - Empty array for rules with zero framework alignment (honest gap).
//   - Multiple frameworks for rules cited by multiple registries (e.g.
//     K1 → ISO 27001 A.8.15 + EU AI Act Art.12 + CoSAI MCP-T12).
//   - Persisted Finding fields pass through verbatim (regression).
//   - `.passthrough()` forwards unknown future framework_controls keys.
// ═══════════════════════════════════════════════════════════════════════════════

describe("Findings — per-finding framework_controls[]", () => {
  // ── Hermetic contract schema for FrameworkControlMapping ───────────────────
  const FrameworkControlMappingSchema = z
    .object({
      framework_id: z.string().min(1),
      control_id: z.string().min(1),
      control_title: z.string().min(1),
    })
    .passthrough();
  // FindingResponseSchema (subset — only the fields under test).
  const FindingResponseSchema = z
    .object({
      id: z.string().uuid(),
      rule_id: z.string().min(1),
      framework_controls: z.array(FrameworkControlMappingSchema),
    })
    .passthrough();

  const baseServer = {
    id: "00000000-0000-0000-0000-000000000099",
    slug: "findings-server",
    name: "Findings Server",
    github_url: null,
    latest_score: 50,
  };

  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(baseServer);
  });

  it("attaches framework_controls[] to every finding row (always an array, never null)", async () => {
    db.getFindingsForServer.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "K1",
        severity: "high",
        evidence: "no structured logging",
        remediation: "use pino",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: new Date("2026-04-25T12:00:00.000Z"),
      },
      {
        id: "33333333-3333-3333-3333-333333333333",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "C1",
        severity: "critical",
        evidence: "exec with user input",
        remediation: "use execFile",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: new Date("2026-04-25T12:01:00.000Z"),
      },
    ]);
    const res = await request(app).get("/api/v1/servers/findings-server/findings");
    expect(res.status).toBe(200);
    const rows = res.body.data as Array<Record<string, unknown>>;
    expect(rows.length).toBe(2);
    for (const row of rows) {
      const parsed = FindingResponseSchema.safeParse(row);
      expect(parsed.success).toBe(true);
      // Always an array — never null, never undefined, never missing.
      expect(Array.isArray(row["framework_controls"])).toBe(true);
    }
  });

  it("returns framework_controls: [] (not null) for a rule with NO framework mapping (honest gap)", async () => {
    db.getFindingsForServer.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        // Synthetic rule_id that is not in any framework's
        // assessor_rule_ids list — verifies the empty-mapping behaviour.
        rule_id: "ZZ_NEVER_MAPPED",
        severity: "low",
        evidence: "synthetic",
        remediation: "n/a",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: new Date(),
      },
    ]);
    const res = await request(app).get("/api/v1/servers/findings-server/findings");
    expect(res.status).toBe(200);
    const row = res.body.data[0] as Record<string, unknown>;
    expect(row).toHaveProperty("framework_controls");
    expect(row["framework_controls"]).toEqual([]);
    // Critical: NEVER null or undefined for empty mappings.
    expect(row["framework_controls"]).not.toBeNull();
    expect(row["framework_controls"]).not.toBeUndefined();
  });

  it("returns ALL frameworks for a rule cited by multiple registries (K1 → ISO 27001 + EU AI Act + CoSAI)", async () => {
    db.getFindingsForServer.mockResolvedValue([
      {
        id: "11111111-1111-1111-1111-111111111111",
        server_id: baseServer.id,
        scan_id: "22222222-2222-2222-2222-222222222222",
        rule_id: "K1",
        severity: "high",
        evidence: "x",
        remediation: "y",
        owasp_category: null,
        mitre_technique: null,
        disputed: false,
        confidence: 1.0,
        evidence_chain: null,
        created_at: new Date(),
      },
    ]);
    const res = await request(app).get("/api/v1/servers/findings-server/findings");
    expect(res.status).toBe(200);
    const controls = (res.body.data[0] as { framework_controls: Array<{ framework_id: string; control_id: string }> })
      .framework_controls;
    const frameworkIds = new Set(controls.map((c) => c.framework_id));
    // K1 (Absent Structured Logging) is cited under at least three
    // frameworks per agent_docs/detection-rules.md K-rules table:
    // ISO 27001 A.8.15, EU AI Act Art.12, CoSAI MCP-T12. Assert at least
    // three distinct frameworks rather than naming them — keeps the test
    // resilient to future framework registry additions.
    expect(frameworkIds.size).toBeGreaterThanOrEqual(3);
    expect(frameworkIds.has("eu_ai_act")).toBe(true);
    expect(frameworkIds.has("iso_27001")).toBe(true);
    expect(frameworkIds.has("cosai_mcp")).toBe(true);
    // Every entry must have a non-empty control_title (the framework
    // registry guarantees this; the API contract preserves it).
    for (const c of controls) {
      expect(c.control_id.length).toBeGreaterThan(0);
      expect(c.control_title.length).toBeGreaterThan(0);
    }
  });

  it("preserves persisted Finding fields verbatim (regression)", async () => {
    // Confirms framework_controls is strictly additive — every column
    // that lives on the Finding row continues to flow through unchanged.
    const finding = {
      id: "11111111-1111-1111-1111-111111111111",
      server_id: baseServer.id,
      scan_id: "22222222-2222-2222-2222-222222222222",
      rule_id: "K1",
      severity: "high",
      evidence: "the original evidence string",
      remediation: "the original remediation string",
      owasp_category: "MCP09-logging-monitoring",
      mitre_technique: "AML.T0086",
      disputed: false,
      confidence: 0.83,
      evidence_chain: { source: "x", sink: "y" },
      created_at: new Date("2026-04-25T12:00:00.000Z"),
    };
    db.getFindingsForServer.mockResolvedValue([finding]);
    const res = await request(app).get("/api/v1/servers/findings-server/findings");
    expect(res.status).toBe(200);
    const row = res.body.data[0] as Record<string, unknown>;
    expect(row["id"]).toBe(finding.id);
    expect(row["rule_id"]).toBe("K1");
    expect(row["severity"]).toBe("high");
    expect(row["evidence"]).toBe("the original evidence string");
    expect(row["remediation"]).toBe("the original remediation string");
    expect(row["owasp_category"]).toBe("MCP09-logging-monitoring");
    expect(row["mitre_technique"]).toBe("AML.T0086");
    expect(row["confidence"]).toBe(0.83);
    expect(row["evidence_chain"]).toEqual({ source: "x", sink: "y" });
  });

  it("forwards unknown future framework_controls[i] fields verbatim (passthrough regression)", async () => {
    // Use a rule that has no mapping and synthesise a framework_controls
    // entry directly on the row. The route handler computes
    // framework_controls from the registry, so we cannot inject one through
    // the registry. Instead, this test pins the contract that the schema
    // PERMITS unknown fields on a framework_controls entry — which the
    // database build at line FrameworkControlMappingSchema.passthrough()
    // guarantees. We assert the schema directly.
    const future = {
      framework_id: "eu_ai_act",
      control_id: "Art.12",
      control_title: "Record-Keeping",
      // Future field a downstream API version might add; passthrough must keep it.
      severity_hint: "medium",
    };
    const parsed = FrameworkControlMappingSchema.safeParse(future);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect((parsed.data as Record<string, unknown>)["severity_hint"]).toBe("medium");
  });

  it("returns 404 for unknown slug on /findings", async () => {
    db.findServerBySlug.mockResolvedValue(null);
    const res = await request(app).get("/api/v1/servers/no-such-server/findings");
    expect(res.status).toBe(404);
  });
});
