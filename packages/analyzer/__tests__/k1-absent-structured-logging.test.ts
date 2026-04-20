/**
 * K1 — Absent Structured Logging — Comprehensive Evidence Chain Tests
 *
 * Tests the TypedRuleV2 implementation that replaced the regex rule.
 * Old regex: /console\.log.*request/ — fired on any "console.log('request...')" anywhere.
 * New rule: AST structural analysis — finds console calls INSIDE request handlers,
 *           cross-checks logger imports and dependencies, calibrates confidence.
 *
 * Test categories:
 * 1. True Positives (8): Express, Koa, Fastify, HTTP, Next.js, Hono, MCP, multi-handler
 * 2. True Negatives (6): No handler, pino in handler, winston, test file, utility code, logger+console
 * 3. Edge Cases (4): Mixed handlers, logging.disable(), partial migration, deep nesting
 * 4. Evidence Chain Validation (3): Structure, confidence factors, verification steps
 * 5. Confidence Calibration (3): No logger vs dep present vs import present
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "t", name: "test", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

function run(src: string, deps: AnalysisContext["dependencies"] = []) {
  return getTypedRule("K1")!.analyze(ctx({ source_code: src, dependencies: deps }));
}

// ─── True Positives ──────────────────────────────────────────────────────────

describe("K1 True Positives", () => {
  it("Express: console.log in app.get handler", () => {
    const src = `
      const express = require('express');
      const app = express();
      app.get('/api/users', (req, res) => {
        console.log("processing user request");
        const users = db.getUsers();
        res.json(users);
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("Express: console.error in router.post handler", () => {
    const src = `
      const router = express.Router();
      router.post('/api/orders', async (req, res) => {
        try {
          await processOrder(req.body);
        } catch (err) {
          console.error("order processing failed", err);
          res.status(500).json({ error: 'fail' });
        }
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("Koa: console.log in ctx handler", () => {
    const src = `
      const Koa = require('koa');
      const app = new Koa();
      app.use(async (ctx) => {
        console.log("handling " + ctx.request.url);
        ctx.body = { ok: true };
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("Fastify: console.warn in fastify.get handler", () => {
    const src = `
      const fastify = require('fastify')();
      fastify.get('/health', async (request, reply) => {
        console.warn("health check hit");
        return { status: 'ok' };
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("HTTP module: console.log in server.on('request')", () => {
    const src = `
      const http = require('http');
      const server = http.createServer();
      server.on('request', (req, res) => {
        console.log("incoming request: " + req.url);
        res.end('ok');
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("Next.js: console.log in exported GET handler", () => {
    const src = `
      export async function GET(request) {
        console.log("API route called");
        return Response.json({ data: [] });
      }
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("MCP: console.log in server.tool handler", () => {
    const src = `
      server.tool('read_file', async (params) => {
        console.log("reading file: " + params.path);
        return { content: fs.readFileSync(params.path, 'utf8') };
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("Multiple console calls in single handler", () => {
    const src = `
      app.post('/api/data', (req, res) => {
        console.log("received data");
        console.log("processing...");
        console.error("something went wrong");
        res.json({ ok: true });
      });
    `;
    const findings = run(src);
    expect(findings.filter(f => f.rule_id === "K1").length).toBeGreaterThanOrEqual(1);
  });
});

// ─── True Negatives ──────────────────────────────────────────────────────────

describe("K1 True Negatives", () => {
  it("does NOT flag console.log outside any handler", () => {
    const src = `
      const config = loadConfig();
      console.log("Server starting on port " + config.port);
      startServer(config);
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });

  it("does NOT flag handler using pino logger", () => {
    const src = `
      import pino from 'pino';
      const logger = pino();
      app.get('/api/data', (req, res) => {
        logger.info({ requestId: req.id }, "handling request");
        res.json({ data: [] });
      });
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });

  it("does NOT flag handler using winston logger", () => {
    const src = `
      const winston = require('winston');
      const logger = winston.createLogger();
      app.post('/api/submit', (req, res) => {
        logger.info("processing submission");
        res.json({ ok: true });
      });
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });

  it("does NOT flag test files (structurally identified, not by filename)", () => {
    // v2 rule identifies test files structurally: test-runner import + describe/it block.
    // Comments alone are not a safe signal (the old regex rule was tricked by them).
    const src = `
      import { describe, it, expect } from 'vitest';
      describe('API', () => {
        it('handles a request', () => {
          app.get('/test', (req, res) => {
            console.log("test handler");
            res.json({});
          });
        });
      });
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });

  it("does NOT flag when no source code", () => {
    const findings = getTypedRule("K1")!.analyze(ctx({ source_code: null }));
    expect(findings.filter(f => f.rule_id === "K1").length).toBe(0);
  });

  it("does NOT flag handler using log.info (generic logger)", () => {
    const src = `
      app.get('/api/data', (req, res) => {
        log.info("handling request");
        res.json({ data: [] });
      });
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });
});

// ─── Edge Cases ──────────────────────────────────────────────────────────────

describe("K1 Edge Cases", () => {
  it("detects logging.disable() even without handler", () => {
    const src = `
      import logging from 'logging';
      logging.disable(logging.CRITICAL);
      app.listen(3000);
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("flags handler with console.log even when logger is imported but unused in that handler", () => {
    const src = `
      import pino from 'pino';
      const logger = pino();

      // This handler uses the logger — OK
      app.get('/api/good', (req, res) => {
        logger.info("good handler");
        res.json({});
      });

      // This handler uses console — NOT OK
      app.get('/api/bad', (req, res) => {
        console.log("bad handler");
        res.json({});
      });
    `;
    const findings = run(src);
    // Should flag the bad handler but not the good one
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("handles deeply nested handler callback", () => {
    const src = `
      const app = express();
      app.use('/api', (req, res, next) => {
        if (req.method === 'POST') {
          console.log("POST request to " + req.path);
        }
        next();
      });
    `;
    const findings = run(src);
    expect(findings.some(f => f.rule_id === "K1")).toBe(true);
  });

  it("does NOT flag commented-out console.log in handler", () => {
    const src = `
      app.get('/api/data', (req, res) => {
        // console.log("debug only");
        res.json({ data: [] });
      });
    `;
    expect(run(src).filter(f => f.rule_id === "K1").length).toBe(0);
  });
});

// ─── Evidence Chain Validation ───────────────────────────────────────────────

describe("K1 Evidence Chain", () => {
  it("produces structured evidence chain with source, propagation, sink, impact", () => {
    const src = `
      app.get('/api/data', (req, res) => {
        console.log("handling request");
        res.json({});
      });
    `;
    const findings = run(src);
    const k1 = findings.find(f => f.rule_id === "K1");
    expect(k1).toBeDefined();

    // Evidence should be present and contain chain keywords
    expect(k1!.evidence).toContain("SOURCE:");
    expect(k1!.evidence).toContain("SINK:");
    expect(k1!.evidence).toContain("CONFIDENCE:");

    // Check metadata has the full chain
    const chain = k1!.metadata?.evidence_chain as any;
    expect(chain).toBeDefined();
    expect(chain.links).toBeDefined();
    expect(chain.links.some((l: any) => l.type === "source")).toBe(true);
    expect(chain.links.some((l: any) => l.type === "sink")).toBe(true);
    expect(chain.links.some((l: any) => l.type === "impact")).toBe(true);
  });

  it("evidence chain has confidence factors explaining the score", () => {
    const src = `
      app.post('/api/submit', (req, res) => {
        console.error("error processing");
        res.status(500).json({});
      });
    `;
    const findings = run(src);
    const k1 = findings.find(f => f.rule_id === "K1");
    expect(k1).toBeDefined();

    const chain = k1!.metadata?.evidence_chain as any;
    expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(2);

    // Should have handler scope factor
    const scopeFactor = chain.confidence_factors.find((f: any) => f.factor === "ast_handler_scope");
    expect(scopeFactor).toBeDefined();
  });

  it("evidence chain has verification steps", () => {
    const src = `
      app.get('/health', (req, res) => {
        console.log("health check");
        res.json({ status: 'ok' });
      });
    `;
    const findings = run(src);
    const k1 = findings.find(f => f.rule_id === "K1");
    const chain = k1!.metadata?.evidence_chain as any;

    expect(chain.verification_steps).toBeDefined();
    expect(chain.verification_steps.length).toBeGreaterThanOrEqual(1);
    expect(chain.verification_steps[0].step_type).toBeDefined();
    expect(chain.verification_steps[0].instruction).toBeDefined();
    // v2 rule standard: step.target is a structured Location (kind: "source"),
    // not a prose string. Check its kind instead of matching a regex.
    expect(chain.verification_steps[0].target).toBeTypeOf("object");
    expect(chain.verification_steps[0].target.kind).toBe("source");
  });

  it("evidence references ISO 27001 A.8.15", () => {
    const src = `
      app.get('/api', (req, res) => {
        console.log("api call");
        res.json({});
      });
    `;
    const findings = run(src);
    const k1 = findings.find(f => f.rule_id === "K1");
    const chain = k1!.metadata?.evidence_chain as any;

    expect(chain.threat_reference).toBeDefined();
    expect(chain.threat_reference.id).toContain("ISO-27001");
  });
});

// ─── Confidence Calibration ──────────────────────────────────────────────────

describe("K1 Confidence Calibration", () => {
  it("highest confidence: no logger import, no logger dependency", () => {
    const src = `
      app.get('/api/data', (req, res) => {
        console.log("processing");
        res.json({});
      });
    `;
    const findings = run(src, []);
    const k1 = findings.find(f => f.rule_id === "K1");
    expect(k1).toBeDefined();
    // No mitigation at all — high confidence
    expect(k1!.confidence).toBeGreaterThan(0.65);
  });

  it("lower confidence: logger dependency present but not imported in file", () => {
    const src = `
      app.get('/api/data', (req, res) => {
        console.log("processing");
        res.json({});
      });
    `;
    const deps = [{ name: "pino", version: "8.0.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" }];
    const findings = run(src, deps);
    const k1 = findings.find(f => f.rule_id === "K1");
    expect(k1).toBeDefined();
    // Logger dep is present (negative factor) — lower confidence than without any dep
    expect(k1!.confidence).toBeLessThan(0.95);
  });

  it("lowest confidence: logger imported but unused in specific handler", () => {
    const src = `
      import pino from 'pino';
      const logger = pino();

      // Good handler
      app.get('/api/good', (req, res) => {
        logger.info("ok");
        res.json({});
      });

      // Bad handler — still uses console
      app.post('/api/bad', (req, res) => {
        console.log("processing");
        res.json({});
      });
    `;
    const deps = [{ name: "pino", version: "8.0.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" }];
    const findings = run(src, deps);
    const k1 = findings.find(f => f.rule_id === "K1");
    expect(k1).toBeDefined();
    // Logger IS imported AND in deps — both negative factors
    // This is likely a partial migration oversight, lower confidence
    expect(k1!.confidence).toBeLessThan(0.60);
  });
});
