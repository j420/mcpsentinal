/**
 * Phase 5 chunk 5.4 — signed compliance report + badge routes.
 *
 * Mocks the DB via vi.mock so the Express app runs without PostgreSQL.
 * Registers stub renderers for HTML / JSON / PDF before importing server.ts
 * so the `getRenderer` lookup finds a matching entry — Agent 2's real
 * renderers can land later without changing this test file.
 */

import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

// ─── Mock the DB module ──────────────────────────────────────────────────────
vi.mock("@mcp-sentinel/database", () => {
  const mockDb = {
    searchServers: vi.fn().mockResolvedValue({ servers: [], total: 0, page: 1, limit: 20 }),
    findServerBySlug: vi.fn().mockResolvedValue(null),
    getToolsForServer: vi.fn().mockResolvedValue([]),
    getFindingsForServer: vi.fn().mockResolvedValue([]),
    getLatestScoreForServer: vi.fn().mockResolvedValue(null),
    getScoreHistory: vi.fn().mockResolvedValue([]),
    getEcosystemStats: vi.fn().mockResolvedValue({ total_servers: 0, scanned: 0 }),
    getAttackChainsForServer: vi.fn().mockResolvedValue([]),
    getDedupStats: vi.fn().mockResolvedValue({}),
    getRiskEdgesForServer: vi.fn().mockResolvedValue([]),
    getComplianceFindingsForServer: vi.fn().mockResolvedValue([]),
    getServersByIds: vi.fn().mockResolvedValue([]),
  };

  return {
    DatabaseQueries: vi.fn(() => mockDb),
    ServerListQuerySchema: {
      safeParse: vi.fn((input) => ({ success: true, data: input })),
    },
    ComplianceFrameworkId: {
      safeParse: vi.fn((input: unknown) => {
        const valid = ["eu_ai_act", "mitre_atlas", "owasp_mcp", "owasp_asi", "cosai", "maestro"];
        return valid.includes(input as string)
          ? { success: true, data: input }
          : { success: false, error: { issues: [] } };
      }),
      options: ["eu_ai_act", "mitre_atlas", "owasp_mcp", "owasp_asi", "cosai", "maestro"],
    },
    migrate: vi.fn().mockResolvedValue(undefined),
    _mockDb: mockDb,
  };
});

// ─── Mock pg ─────────────────────────────────────────────────────────────────
vi.mock("pg", () => ({
  default: {
    Pool: vi.fn(() => ({
      connect: vi.fn(),
      end: vi.fn(),
      query: vi.fn(),
    })),
  },
}));

process.env["NODE_ENV"] = "test";

// ─── Register stub renderers BEFORE server.ts imports the module graph ──────
// The compliance-reports package's renderer registry lives at module-scope;
// any import path that pulls it in will share the same registry. Registering
// before server.ts runs ensures the first render() call succeeds.
const STUB_HTML = "<!doctype html><html><body>stub html report</body></html>";
const STUB_JSON_FIELD = "stub-json-body";
const STUB_PDF = Buffer.from("%PDF-1.4\n% stub\n%%EOF\n", "utf-8");

type StubbedSigned = {
  report: { framework: { id: string }; server: { slug: string } };
  attestation: {
    algorithm: string;
    signature: string;
    key_id: string;
    signed_at: string;
    signer: string;
    canonicalization: string;
  };
};

async function registerStubs(): Promise<void> {
  const { registerRenderer, FRAMEWORK_IDS } = await import(
    "@mcp-sentinel/compliance-reports"
  );
  for (const framework of FRAMEWORK_IDS) {
    registerRenderer("json", framework, {
      format: "json",
      contentType: "application/json; charset=utf-8",
      filenameSuffix: "json",
      // JSON renderer emits the whole signed envelope — that's what
      // a real JSON renderer will do. We inject a stub marker so tests
      // can distinguish a stub from a real render.
      render: (signed) =>
        JSON.stringify({
          ...signed,
          _stub_marker: STUB_JSON_FIELD,
        }),
    });
    registerRenderer("html", framework, {
      format: "html",
      contentType: "text/html; charset=utf-8",
      filenameSuffix: "html",
      render: (signed) => {
        // Embed signature inside the body so the "body contains signature"
        // assertion passes — mirrors what Agent 2's real renderer does.
        return `${STUB_HTML}<!-- signature=${signed.attestation.signature} -->`;
      },
    });
    registerRenderer("pdf", framework, {
      format: "pdf",
      contentType: "application/pdf",
      filenameSuffix: "pdf",
      render: (signed) => {
        const sig = Buffer.from(`\n%sig=${signed.attestation.signature}\n`, "utf-8");
        return Buffer.concat([STUB_PDF, sig]);
      },
    });
  }
}

// ─── Import app + hook up stubs ─────────────────────────────────────────────
type MockDb = {
  findServerBySlug: ReturnType<typeof vi.fn>;
  getFindingsForServer: ReturnType<typeof vi.fn>;
  getAttackChainsForServer: ReturnType<typeof vi.fn>;
};

let app: import("express").Express;
let _resetRateLimiters: () => void;
let db: MockDb;

beforeAll(async () => {
  await registerStubs();
  const mod = await import("../server.js");
  app = mod.app;
  _resetRateLimiters = mod._resetRateLimiters;
  const dbMod = (await import("@mcp-sentinel/database")) as unknown as {
    _mockDb: MockDb;
  };
  db = dbMod._mockDb;
});

// ─── Fixture helpers ────────────────────────────────────────────────────────
const SERVER_FIXTURE = {
  id: "00000000-0000-0000-0000-000000000001",
  name: "Demo Server",
  slug: "demo-server",
  description: "A demo",
  author: null,
  github_url: null,
  npm_package: null,
  pypi_package: null,
  category: null,
  language: null,
  license: null,
  github_stars: null,
  npm_downloads: null,
  last_commit: null,
  latest_score: 80,
  last_scanned_at: new Date("2026-04-23T00:00:00Z"),
  endpoint_url: null,
  tool_count: 0,
  connection_status: "success" as const,
  server_version: null,
  server_instructions: null,
  created_at: new Date("2026-04-20T00:00:00Z"),
  updated_at: new Date("2026-04-23T00:00:00Z"),
};

const FINDING_FIXTURE = {
  id: "00000000-0000-0000-0000-0000000000aa",
  server_id: SERVER_FIXTURE.id,
  scan_id: "00000000-0000-0000-0000-0000000000bb",
  rule_id: "C1",
  severity: "critical" as const,
  evidence: "Synthetic evidence",
  remediation: "Apply recommended fix",
  owasp_category: "MCP03" as const,
  mitre_technique: "AML.T0054",
  disputed: false,
  confidence: 0.99,
  evidence_chain: null,
  created_at: new Date("2026-04-23T00:00:00Z"),
};

beforeEach(() => {
  vi.clearAllMocks();
  db.findServerBySlug.mockResolvedValue(null);
  db.getFindingsForServer.mockResolvedValue([]);
  db.getAttackChainsForServer.mockResolvedValue([]);
  _resetRateLimiters();
});

// ═══════════════════════════════════════════════════════════════════════════
// 404s on invalid input
// ═══════════════════════════════════════════════════════════════════════════

describe("compliance report — 404 paths", () => {
  it("returns 404 for unknown server slug", async () => {
    db.findServerBySlug.mockResolvedValue(null);
    const res = await request(app).get(
      "/api/v1/servers/unknown-slug/compliance/eu_ai_act.json",
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("server_not_found");
  });

  it("returns 404 for unknown framework id", async () => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/not-a-framework.json",
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("unknown_framework");
    expect(res.body.valid).toContain("eu_ai_act");
  });

  it("returns 404 for unknown format suffix (no route match)", async () => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    // .xml is not a registered route → Express falls through to the global
    // 404 handler. The point is that the endpoint definitively does not
    // serve arbitrary formats.
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.xml",
    );
    expect(res.status).toBe(404);
  });

  it("returns 404 badge for unknown framework", async () => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/not-real/badge.svg",
    );
    expect(res.status).toBe(404);
    expect(res.body.error).toBe("unknown_framework");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Signed report happy paths
// ═══════════════════════════════════════════════════════════════════════════

describe("compliance report — JSON", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    db.getFindingsForServer.mockResolvedValue([FINDING_FIXTURE]);
  });

  it("returns 200 with a signed JSON body", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    const body = JSON.parse(res.text) as StubbedSigned;
    expect(body.report).toBeDefined();
    expect(body.attestation.signature).toBeTruthy();
    expect(body.attestation.algorithm).toBe("HMAC-SHA256");
    expect(body.attestation.canonicalization).toBe("RFC8785");
    expect(body.attestation.signer).toBe("mcp-sentinel/v1");
  });

  it("signature in body matches signature in header", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
    );
    const body = JSON.parse(res.text) as StubbedSigned;
    expect(res.headers["x-mcp-sentinel-signature"]).toBe(body.attestation.signature);
    expect(res.headers["x-mcp-sentinel-key-id"]).toBe(body.attestation.key_id);
    expect(res.headers["x-mcp-sentinel-signed-at"]).toBe(body.attestation.signed_at);
    expect(res.headers["x-mcp-sentinel-algorithm"]).toBe("HMAC-SHA256");
    expect(res.headers["x-mcp-sentinel-canonicalization"]).toBe("RFC8785");
  });

  it("signature verifies via verifyReport with the dev signing context", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
    );
    const body = JSON.parse(res.text) as StubbedSigned;
    const { resolveSigningContextFromEnv, verifyReport } = await import(
      "@mcp-sentinel/compliance-reports"
    );
    const ctx = resolveSigningContextFromEnv();
    // Strip the stub marker before verification — the signature was
    // computed over the canonicalised report body, NOT the stub's
    // additional field.
    type VerifiableSigned = Parameters<typeof verifyReport>[0];
    const verifiable = {
      report: (body as unknown as VerifiableSigned).report,
      attestation: (body as unknown as VerifiableSigned).attestation,
    };
    const verdict = verifyReport(verifiable, ctx);
    expect(verdict.valid).toBe(true);
  });

  it("sets Cache-Control: public, max-age=300", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
    );
    expect(res.headers["cache-control"]).toContain("max-age=300");
  });

  it("surfaces dev-key warning header when COMPLIANCE_SIGNING_KEY is unset", async () => {
    const prevKey = process.env["COMPLIANCE_SIGNING_KEY"];
    const prevKeyId = process.env["COMPLIANCE_SIGNING_KEY_ID"];
    delete process.env["COMPLIANCE_SIGNING_KEY"];
    delete process.env["COMPLIANCE_SIGNING_KEY_ID"];
    try {
      const res = await request(app).get(
        "/api/v1/servers/demo-server/compliance/eu_ai_act.json",
      );
      expect(res.headers["x-mcp-sentinel-warning"]).toBe("dev-key-in-use");
    } finally {
      if (prevKey !== undefined) process.env["COMPLIANCE_SIGNING_KEY"] = prevKey;
      if (prevKeyId !== undefined) process.env["COMPLIANCE_SIGNING_KEY_ID"] = prevKeyId;
    }
  });
});

describe("compliance report — HTML", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    db.getFindingsForServer.mockResolvedValue([FINDING_FIXTURE]);
  });

  it("returns 200 with text/html Content-Type", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.html",
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    expect(res.text).toMatch(/^<!doctype html>/i);
  });

  it("embeds signature in body + header", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act.html",
    );
    const sigHeader = res.headers["x-mcp-sentinel-signature"];
    expect(sigHeader).toBeTruthy();
    expect(res.text).toContain(`signature=${sigHeader}`);
  });
});

describe("compliance report — PDF", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    db.getFindingsForServer.mockResolvedValue([FINDING_FIXTURE]);
  });

  it("returns 200 with application/pdf and a %PDF- magic", async () => {
    const res = await request(app)
      .get("/api/v1/servers/demo-server/compliance/eu_ai_act.pdf")
      .buffer(true)
      .parse((r, cb) => {
        const chunks: Buffer[] = [];
        r.on("data", (c: Buffer) => chunks.push(c));
        r.on("end", () => cb(null, Buffer.concat(chunks)));
      });
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/pdf/);
    const body = res.body as Buffer;
    const head = body.subarray(0, 5).toString("utf-8");
    expect(head).toBe("%PDF-");
  });

  it("two requests against same scan data return byte-identical PDF", async () => {
    const fetch = async (): Promise<Buffer> => {
      const r = await request(app)
        .get("/api/v1/servers/demo-server/compliance/eu_ai_act.pdf")
        .buffer(true)
        .parse((r2, cb) => {
          const chunks: Buffer[] = [];
          r2.on("data", (c: Buffer) => chunks.push(c));
          r2.on("end", () => cb(null, Buffer.concat(chunks)));
        });
      return r.body as Buffer;
    };
    const a = await fetch();
    const b = await fetch();
    expect(Buffer.compare(a, b)).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Badge SVG
// ═══════════════════════════════════════════════════════════════════════════

describe("compliance badge — SVG", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    db.getFindingsForServer.mockResolvedValue([]);
  });

  it("returns 200 image/svg+xml for eu_ai_act", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act/badge.svg",
    );
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/image\/svg\+xml/);
    const body = res.text ?? Buffer.from(res.body as Buffer).toString("utf-8");
    expect(body).toContain("<svg");
    expect(body).toContain("#003399"); // EU blue
    expect(body).toContain("EU AI Act");
  });

  it("includes attestation headers on badge responses", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/iso_27001/badge.svg",
    );
    expect(res.headers["x-mcp-sentinel-signature"]).toBeTruthy();
    expect(res.headers["x-mcp-sentinel-key-id"]).toBeTruthy();
    expect(res.headers["x-mcp-sentinel-signed-at"]).toBeTruthy();
    expect(res.headers["x-mcp-sentinel-algorithm"]).toBe("HMAC-SHA256");
    expect(res.headers["x-mcp-sentinel-canonicalization"]).toBe("RFC8785");
  });

  it("badge signature in headers matches the signature embedded in SVG comment", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/maestro/badge.svg",
    );
    const sig = res.headers["x-mcp-sentinel-signature"];
    expect(sig).toBeTruthy();
    const body = res.text ?? Buffer.from(res.body as Buffer).toString("utf-8");
    expect(body).toContain(`signature=${sig}`);
  });

  it("includes CSP default-src 'none' on badge", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act/badge.svg",
    );
    expect(res.headers["content-security-policy"]).toMatch(/default-src\s+'none'/);
  });

  it("sets Cache-Control on badge", async () => {
    const res = await request(app).get(
      "/api/v1/servers/demo-server/compliance/eu_ai_act/badge.svg",
    );
    expect(res.headers["cache-control"]).toContain("max-age=300");
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// Cross-framework coverage — every framework id resolves
// ═══════════════════════════════════════════════════════════════════════════

describe("compliance report — all 7 frameworks", () => {
  beforeEach(() => {
    db.findServerBySlug.mockResolvedValue(SERVER_FIXTURE);
    db.getFindingsForServer.mockResolvedValue([]);
  });

  const frameworks = [
    "eu_ai_act",
    "iso_27001",
    "owasp_mcp",
    "owasp_asi",
    "cosai_mcp",
    "maestro",
    "mitre_atlas",
  ];

  for (const fw of frameworks) {
    it(`returns 200 JSON for ${fw}`, async () => {
      const res = await request(app).get(
        `/api/v1/servers/demo-server/compliance/${fw}.json`,
      );
      expect(res.status).toBe(200);
      const body = JSON.parse(res.text) as StubbedSigned;
      expect(body.report.framework.id).toBe(fw);
    });

    it(`returns 200 badge for ${fw}`, async () => {
      const res = await request(app).get(
        `/api/v1/servers/demo-server/compliance/${fw}/badge.svg`,
      );
      expect(res.status).toBe(200);
      const body = res.text ?? Buffer.from(res.body as Buffer).toString("utf-8");
      expect(body).toContain("<svg");
    });
  }
});
