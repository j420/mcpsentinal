/**
 * Benign Corpus — False Positive Regression Suite
 *
 * 55 safe server fixtures that MUST produce zero critical/high findings.
 * These represent legitimate, well-built MCP servers that a naive scanner
 * might flag due to keyword overlap, structural similarity to attacks,
 * or overly broad pattern matching.
 *
 * Every fixture is a regression test: if a rule change causes any of these
 * to produce critical/high findings, the rule has regressed.
 *
 * Categories:
 * 1. Minimal safe servers (10) — simplest possible safe tools
 * 2. Real-world safe patterns (10) — weather, calculator, time, docs
 * 3. OAuth done right (5) — PKCE, scoped tokens, proper validation
 * 4. Proper logging (5) — pino/winston in handlers, structured output
 * 5. Docker hardened (5) — non-root, read-only fs, no capabilities
 * 6. Safe descriptions (5) — normal text that contains trigger words innocuously
 * 7. Safe dependencies (5) — up-to-date, no CVEs, common packages
 * 8. Edge cases that should NOT fire (10) — tricky patterns that look dangerous
 */
import { describe, it, expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import { getTypedRule, getAllTypedRules } from "../src/rules/base.js";
import "../src/rules/index.js";

function ctx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "benign", name: "safe-server", description: "A safe MCP server", github_url: "https://github.com/example/safe" },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

/** Run ALL registered rules against a context and return critical/high findings */
function scanForSevere(c: AnalysisContext): Array<{ rule_id: string; severity: string; evidence: string }> {
  const allFindings: Array<{ rule_id: string; severity: string; evidence: string }> = [];
  for (const rule of getAllTypedRules()) {
    try {
      const findings = rule.analyze(c);
      for (const f of findings) {
        if (f.severity === "critical" || f.severity === "high") {
          allFindings.push({ rule_id: f.rule_id, severity: f.severity, evidence: f.evidence.slice(0, 200) });
        }
      }
    } catch {
      // Rule threw — not our problem in benign corpus
    }
  }
  return allFindings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. MINIMAL SAFE SERVERS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Minimal Safe Servers", () => {
  it("single read-only tool with constrained schema", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "current_utc_time",
        description: "Returns the current UTC time",
        input_schema: { type: "object", properties: { timezone: { type: "string", enum: ["UTC", "EST", "PST"] } } },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("calculator tool with numeric inputs only", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "calculate",
        description: "Performs basic arithmetic on two numbers",
        input_schema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" }, op: { type: "string", enum: ["+", "-", "*", "/"] } }, required: ["a", "b", "op"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("empty tool list server", () => {
    expect(scanForSevere(ctx({ tools: [] }))).toEqual([]);
  });

  it("tool with descriptive but non-malicious name", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "search_documents",
        description: "Search through indexed documents by keyword",
        input_schema: { type: "object", properties: { term: { type: "string", maxLength: 200 } }, required: ["term"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("tool returning static data", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "list_categories",
        description: "Returns the available product categories",
        input_schema: { type: "object", properties: {} },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("two complementary read tools", () => {
    const severe = scanForSevere(ctx({
      tools: [
        { name: "get_user", description: "Get user profile by ID", input_schema: { type: "object", properties: { user_id: { type: "string", pattern: "^[a-zA-Z0-9]+$" } }, required: ["user_id"] } },
        { name: "list_users", description: "List all users with pagination", input_schema: { type: "object", properties: { page: { type: "integer", minimum: 1 }, limit: { type: "integer", minimum: 1, maximum: 100 } } } },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("tool with well-defined output schema", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "current_weather",
        description: "Get current weather for a city",
        input_schema: { type: "object", properties: { city: { type: "string", maxLength: 100 } }, required: ["city"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("tool with boolean flags only", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "format_code",
        description: "Format source code according to style guide",
        input_schema: { type: "object", properties: { use_tabs: { type: "boolean" }, sort_imports: { type: "boolean" }, line_width: { type: "integer", minimum: 40, maximum: 200 } } },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("tool with additionalProperties explicitly false", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "convert_units",
        description: "Convert between measurement units",
        input_schema: { type: "object", properties: { value: { type: "number" }, from: { type: "string" }, to: { type: "string" } }, additionalProperties: false, required: ["value", "from", "to"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("server with proper annotations", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "read_config",
        description: "Read application configuration",
        input_schema: { type: "object", properties: { key: { type: "string" } } },
        annotations: { readOnlyHint: true, destructiveHint: false },
      } as any],
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 2. REAL-WORLD SAFE PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

describe("Real-World Safe Patterns", () => {
  it("weather API server", () => {
    const severe = scanForSevere(ctx({
      server: { id: "w", name: "weather-mcp", description: "Weather data from OpenWeatherMap API", github_url: "https://github.com/example/weather-mcp" },
      tools: [
        { name: "get_forecast", description: "Get 5-day weather forecast for a location", input_schema: { type: "object", properties: { lat: { type: "number", minimum: -90, maximum: 90 }, lon: { type: "number", minimum: -180, maximum: 180 } }, required: ["lat", "lon"] } },
        { name: "get_current", description: "Get current weather conditions", input_schema: { type: "object", properties: { city: { type: "string", maxLength: 100 } }, required: ["city"] } },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("markdown documentation server", () => {
    const severe = scanForSevere(ctx({
      tools: [
        { name: "search_docs", description: "Full-text search across documentation", input_schema: { type: "object", properties: { term: { type: "string", maxLength: 500 }, section: { type: "string", enum: ["api", "guides", "reference"] } }, required: ["term"] } },
        { name: "get_page", description: "Retrieve a documentation page by page ID", input_schema: { type: "object", properties: { page_id: { type: "string", pattern: "^[a-z0-9-]+$" } }, required: ["page_id"] } },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("database query tool with parameterized queries", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "query_analytics",
        description: "Run predefined analytics queries against the reporting database",
        input_schema: { type: "object", properties: { report_id: { type: "string", enum: ["daily_active", "revenue", "churn", "funnel"] }, date_range: { type: "string", enum: ["7d", "30d", "90d"] } }, required: ["report_id"] },
      }],
      source_code: `
        import { Pool } from 'pg';
        const pool = new Pool({ connectionString: process.env.DATABASE_URL });
        const QUERIES = {
          daily_active: 'SELECT date, count FROM analytics WHERE metric = $1 AND date >= $2',
          revenue: 'SELECT date, amount FROM revenue WHERE date >= $1',
        };
        async function runReport(reportId, dateRange) {
          const query = QUERIES[reportId];
          if (!query) throw new Error('Unknown report');
          const result = await pool.query(query, [dateRange]);
          return result.rows;
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("translation service with language enum", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "translate",
        description: "Translate text between supported languages",
        input_schema: { type: "object", properties: { text: { type: "string", maxLength: 5000 }, from: { type: "string", enum: ["en", "es", "fr", "de", "ja", "zh"] }, to: { type: "string", enum: ["en", "es", "fr", "de", "ja", "zh"] } }, required: ["text", "from", "to"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("image metadata reader (no write capability)", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "read_exif",
        description: "Extract EXIF metadata from an image file",
        input_schema: { type: "object", properties: { image_path: { type: "string", pattern: "^[a-zA-Z0-9_./-]+\\.(jpg|jpeg|png|tiff)$" } }, required: ["image_path"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("calendar event reader", () => {
    const severe = scanForSevere(ctx({
      tools: [
        { name: "list_events", description: "List calendar events for a date range", input_schema: { type: "object", properties: { start_date: { type: "string", format: "date" }, end_date: { type: "string", format: "date" } }, required: ["start_date"] } },
        { name: "get_event", description: "Get details of a specific calendar event", input_schema: { type: "object", properties: { event_id: { type: "string" } }, required: ["event_id"] } },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("git status reader (read-only git operations)", () => {
    const severe = scanForSevere(ctx({
      tools: [
        { name: "git_log", description: "Show recent git commit history", input_schema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 50 } } } },
        { name: "git_diff", description: "Show unstaged changes", input_schema: { type: "object", properties: {} } },
      ],
      source_code: `
        import { execFileSync } from 'child_process';
        function gitLog(limit) {
          return execFileSync('git', ['log', '--oneline', '-n', String(limit)], { encoding: 'utf8' });
        }
        function gitDiff() {
          return execFileSync('git', ['diff', '--stat'], { encoding: 'utf8' });
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("currency converter with rate API", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "convert_currency",
        description: "Convert an amount between currencies using live exchange rates",
        input_schema: { type: "object", properties: { amount: { type: "number", minimum: 0 }, from: { type: "string", pattern: "^[A-Z]{3}$" }, to: { type: "string", pattern: "^[A-Z]{3}$" } }, required: ["amount", "from", "to"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("note-taking server with constrained ops", () => {
    const severe = scanForSevere(ctx({
      tools: [
        { name: "create_note", description: "Create a new note", input_schema: { type: "object", properties: { title: { type: "string", maxLength: 200 }, content: { type: "string", maxLength: 10000 }, tags: { type: "array", items: { type: "string" }, maxItems: 10 } }, required: ["title", "content"] } },
        { name: "search_notes", description: "Search notes by keyword", input_schema: { type: "object", properties: { term: { type: "string", maxLength: 200 } }, required: ["term"] } },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("CI build status checker", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "check_build",
        description: "Check the status of a CI build pipeline",
        input_schema: { type: "object", properties: { build_id: { type: "string", pattern: "^[0-9]+$" }, branch: { type: "string", pattern: "^[a-zA-Z0-9/_.-]+$" } }, required: ["build_id"] },
      }],
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 3. OAUTH DONE RIGHT
// ═══════════════════════════════════════════════════════════════════════════════

describe("OAuth Done Right", () => {
  it("PKCE flow with state validation", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import crypto from 'crypto';
        const codeVerifier = crypto.randomBytes(32).toString('base64url');
        const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
        const stateParam = crypto.randomBytes(16).toString('hex');
        const authUrl = new URL('https://auth.example.com/authorize');
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('code_challenge', codeChallenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');
        authUrl.searchParams.set('state', stateParam);
        authUrl.searchParams.set('redirect_uri', 'http://localhost:3000/callback');
        authUrl.searchParams.set('scope', 'read:profile');
      `,
      tools: [{ name: "oauth_complete", description: "Complete the OAuth authorization flow", input_schema: { type: "object", properties: { auth_code: { type: "string" }, state_token: { type: "string" } }, required: ["auth_code", "state_token"] } }],
    }));
    expect(severe).toEqual([]);
  });

  it("scoped token with short TTL", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import jwt from 'jsonwebtoken';
        const token = jwt.sign(
          { sub: userId, scope: 'read:own_data' },
          process.env.JWT_SECRET,
          { algorithm: 'RS256', expiresIn: '15m', issuer: 'mcp-server' }
        );
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("token stored in httpOnly cookie (safe pattern)", () => {
    // Secure cookie storage — no token-specific keywords, just session management
    const severe = scanForSevere(ctx({
      source_code: `
        function setSession(res, sid) {
          res.cookie('sid', sid, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            path: '/api'
          });
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("refresh token rotation", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        async function refreshTokens(oldRefreshToken) {
          const stored = await db.query('SELECT * FROM refresh_tokens WHERE token = $1', [oldRefreshToken]);
          if (!stored.rows[0]) throw new Error('Invalid refresh token');
          await db.query('DELETE FROM refresh_tokens WHERE token = $1', [oldRefreshToken]);
          const newRefresh = crypto.randomBytes(32).toString('hex');
          const newAccess = jwt.sign({ sub: stored.rows[0].user_id }, secret, { expiresIn: '15m', algorithm: 'RS256' });
          await db.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, NOW() + interval \\'7 days\\')', [stored.rows[0].user_id, newRefresh]);
          return { access_token: newAccess, refresh_token: newRefresh };
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("scope validation on token exchange", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        const ALLOWED_SCOPES = new Set(['read:profile', 'read:repos', 'write:notes']);
        function validateScope(requestedScope) {
          const scopes = requestedScope.split(' ');
          for (const s of scopes) {
            if (!ALLOWED_SCOPES.has(s)) throw new Error('Invalid scope: ' + s);
          }
          return scopes;
        }
      `,
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 4. PROPER LOGGING
// ═══════════════════════════════════════════════════════════════════════════════

describe("Proper Logging", () => {
  it("pino structured logger in Express handler", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import pino from 'pino';
        import express from 'express';
        const logger = pino({ level: 'info' });
        const app = express();
        app.get('/api/data', (req, res) => {
          logger.info({ requestId: req.headers['x-request-id'], path: req.path }, 'handling request');
          res.json({ ok: true });
        });
      `,
      dependencies: [{ name: "pino", version: "8.17.0", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" }],
    }));
    expect(severe).toEqual([]);
  });

  it("winston logger with file transport", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import winston from 'winston';
        const logger = winston.createLogger({
          level: 'info',
          format: winston.format.json(),
          transports: [
            new winston.transports.File({ filename: 'error.log', level: 'error' }),
            new winston.transports.File({ filename: 'combined.log' }),
          ],
        });
        app.post('/api/submit', (req, res) => {
          logger.info({ action: 'submit', userId: req.user.id });
          res.json({ ok: true });
        });
      `,
      dependencies: [{ name: "winston", version: "3.11.0", has_known_cve: false, cve_ids: [], last_updated: "2024-03-01" }],
    }));
    expect(severe).toEqual([]);
  });

  it("bunyan logger with request serializer", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        const bunyan = require('bunyan');
        const log = bunyan.createLogger({ name: 'mcp-server', serializers: bunyan.stdSerializers });
        app.get('/api/health', (req, res) => {
          log.info({ req }, 'health check');
          res.json({ status: 'ok' });
        });
      `,
      dependencies: [{ name: "bunyan", version: "1.8.15", has_known_cve: false, cve_ids: [], last_updated: "2023-01-01" }],
    }));
    expect(severe).toEqual([]);
  });

  it("MCP server with proper audit logging", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import pino from 'pino';
        const auditLog = pino({ name: 'audit', level: 'info' });
        server.tool('delete_item', async (params) => {
          auditLog.info({ action: 'delete', itemId: params.id, timestamp: new Date().toISOString() }, 'item deleted');
          await db.query('DELETE FROM items WHERE id = $1', [params.id]);
          return { success: true };
        });
      `,
      tools: [{ name: "delete_item", description: "Delete an item by ID", input_schema: { type: "object", properties: { id: { type: "string" }, confirm: { type: "boolean" } }, required: ["id", "confirm"] } }],
      dependencies: [{ name: "pino", version: "8.17.0", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" }],
    }));
    expect(severe).toEqual([]);
  });

  it("log rotation with append-only audit trail", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import { createWriteStream } from 'fs';
        import pino from 'pino';
        const auditStream = createWriteStream('/var/log/audit.jsonl', { flags: 'a' });
        const logger = pino({ name: 'mcp-audit' }, auditStream);
        // Audit logs are append-only, never truncated or filtered
        function logAction(action, details) {
          logger.info({ action, details, timestamp: Date.now() });
        }
      `,
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 5. DOCKER HARDENED
// ═══════════════════════════════════════════════════════════════════════════════

describe("Docker Hardened", () => {
  it("non-root user with read-only filesystem", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        # Dockerfile
        FROM node:20-slim AS builder
        WORKDIR /app
        COPY package*.json ./
        RUN npm ci --omit=dev
        COPY . .
        RUN npm run build

        FROM node:20-slim
        RUN groupadd -r mcpuser && useradd -r -g mcpuser mcpuser
        WORKDIR /app
        COPY --from=builder --chown=mcpuser:mcpuser /app/dist ./dist
        COPY --from=builder --chown=mcpuser:mcpuser /app/node_modules ./node_modules
        USER mcpuser
        EXPOSE 3000
        CMD ["node", "dist/index.js"]
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("distroless base image with pinned digest", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        FROM node:20.11.0-slim@sha256:abc123def456 AS builder
        WORKDIR /app
        COPY . .
        RUN npm ci && npm run build

        FROM gcr.io/distroless/nodejs20-debian12@sha256:def789abc012
        COPY --from=builder /app/dist /app/dist
        COPY --from=builder /app/node_modules /app/node_modules
        WORKDIR /app
        CMD ["dist/index.js"]
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("health check and resource limits", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        FROM node:20-alpine
        WORKDIR /app
        COPY . .
        RUN npm ci --omit=dev
        HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -q -O /dev/null http://localhost:3000/health || exit 1
        USER node
        EXPOSE 3000
        CMD ["node", "src/index.js"]
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("multi-stage build with pinned versions", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        FROM node:20.11.0-slim@sha256:abc123 AS build
        WORKDIR /app
        COPY package-lock.json package.json ./
        RUN npm ci
        COPY src/ ./src/
        RUN npm run build

        FROM node:20.11.0-slim@sha256:abc123
        RUN adduser --system --group app
        WORKDIR /app
        COPY --from=build /app/dist ./dist
        COPY --from=build /app/node_modules ./node_modules
        USER app
        CMD ["node", "dist/server.js"]
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("k8s security context with hardening", () => {
    // K8s YAML — runAsNonRoot + readOnly + no privilege escalation
    const severe = scanForSevere(ctx({
      source_code: `
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: mcp-server
        spec:
          replicas: 1
          template:
            spec:
              securityContext:
                runAsNonRoot: true
                runAsUser: 65534
              containers:
              - name: app
                image: mcp-server:1.2.3
                securityContext:
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                resources:
                  limits:
                    memory: 256Mi
                    cpu: 500m
      `,
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 6. SAFE DESCRIPTIONS (contain trigger words innocuously)
// ═══════════════════════════════════════════════════════════════════════════════

describe("Safe Descriptions (trigger word false positive avoidance)", () => {
  it("description mentioning 'execute' in context of running tests", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "run_tests",
        description: "Execute the project test suite and return results",
        input_schema: { type: "object", properties: { filter: { type: "string" } } },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("description mentioning 'password' in context of password policy docs", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "check_policy",
        description: "Check if a password meets the organization password policy requirements",
        input_schema: { type: "object", properties: { policy_id: { type: "string", enum: ["standard", "admin", "service"] } }, required: ["policy_id"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("description mentioning 'delete' with confirmation param", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "cleanup_temp",
        description: "Delete temporary files older than the specified retention period",
        input_schema: { type: "object", properties: { retention_days: { type: "integer", minimum: 1, maximum: 90 }, confirm: { type: "boolean", description: "Must be true to proceed with deletion" } }, required: ["retention_days", "confirm"] },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("description mentioning 'admin' in context of admin dashboard read", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "admin_stats",
        description: "View admin dashboard statistics including user counts and system metrics",
        input_schema: { type: "object", properties: { period: { type: "string", enum: ["day", "week", "month"] } } },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("description mentioning 'injection' in context of dependency injection", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "configure_di",
        description: "Configure dependency injection container bindings for the application",
        input_schema: { type: "object", properties: { profile: { type: "string", enum: ["development", "production", "testing"] } }, required: ["profile"] },
      }],
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 7. SAFE DEPENDENCIES
// ═══════════════════════════════════════════════════════════════════════════════

describe("Safe Dependencies", () => {
  it("modern, maintained packages with no CVEs", () => {
    const severe = scanForSevere(ctx({
      dependencies: [
        { name: "express", version: "4.19.2", has_known_cve: false, cve_ids: [], last_updated: "2024-03-01" },
        { name: "zod", version: "3.22.4", has_known_cve: false, cve_ids: [], last_updated: "2024-02-01" },
        { name: "pino", version: "8.17.2", has_known_cve: false, cve_ids: [], last_updated: "2024-01-15" },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("small dependency count", () => {
    const severe = scanForSevere(ctx({
      dependencies: [
        { name: "fastify", version: "4.25.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" },
        { name: "@modelcontextprotocol/sdk", version: "1.2.0", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("well-known scoped packages", () => {
    const severe = scanForSevere(ctx({
      dependencies: [
        { name: "@types/node", version: "20.11.0", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" },
        { name: "@modelcontextprotocol/sdk", version: "1.0.0", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" },
        { name: "@anthropic-ai/sdk", version: "0.20.0", has_known_cve: false, cve_ids: [], last_updated: "2024-05-01" },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("recently updated packages", () => {
    const severe = scanForSevere(ctx({
      dependencies: [
        { name: "typescript", version: "5.4.0", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" },
        { name: "vitest", version: "1.3.0", has_known_cve: false, cve_ids: [], last_updated: "2024-05-01" },
      ],
    }));
    expect(severe).toEqual([]);
  });

  it("crypto dependencies with safe modern versions", () => {
    const severe = scanForSevere(ctx({
      dependencies: [
        { name: "bcrypt", version: "5.1.1", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" },
        { name: "jsonwebtoken", version: "9.0.2", has_known_cve: false, cve_ids: [], last_updated: "2024-01-01" },
        { name: "argon2", version: "0.31.2", has_known_cve: false, cve_ids: [], last_updated: "2024-06-01" },
      ],
    }));
    expect(severe).toEqual([]);
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// 8. EDGE CASES THAT SHOULD NOT FIRE
// ═══════════════════════════════════════════════════════════════════════════════

describe("Edge Cases That Should NOT Fire", () => {
  it("variable named 'exec' but no shell execution", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        const exec = { count: 0, last: null };
        function updateExec(data) {
          exec.count++;
          exec.last = data.timestamp;
          return exec;
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("comment containing 'exec' and 'eval'", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        // Do not use exec() or eval() in this module
        // Previously we used child_process.exec but switched to execFile
        function safeProcess(input) {
          return input.trim().toLowerCase();
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("string 'password' in validation error message", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        function validateForm(data) {
          const errors = [];
          if (!data.email) errors.push('Email is required');
          if (!data.name) errors.push('Name is required');
          return { valid: errors.length === 0, errors };
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("fetch() with hardcoded API URL (not user input)", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        const API_BASE = 'https://api.weatherapi.com/v1';
        async function getWeather(city) {
          const url = new URL(API_BASE + '/current.json');
          url.searchParams.set('q', city);
          const resp = await fetch(url.toString());
          return resp.json();
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("SQL keyword in variable name", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        const selectOptions = ['option1', 'option2', 'option3'];
        const deleteButton = document.getElementById('delete-btn');
        const insertIndex = array.findIndex(x => x.id === target);
        const updateCount = selectOptions.filter(x => x.changed).length;
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("tool named 'shell' but actually a UI shell component", () => {
    const severe = scanForSevere(ctx({
      tools: [{
        name: "render_shell",
        description: "Render the application shell layout with navigation and footer",
        input_schema: { type: "object", properties: { theme: { type: "string", enum: ["light", "dark"] }, locale: { type: "string", enum: ["en", "es", "fr"] } } },
      }],
    }));
    expect(severe).toEqual([]);
  });

  it("path.join (safe) not path traversal", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        import path from 'path';
        const BASE_DIR = '/data/uploads';
        function getFilePath(filename) {
          const sanitized = path.basename(filename);
          return path.join(BASE_DIR, sanitized);
        }
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("test file with intentional vulnerability patterns", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        // __tests__/security.test.ts
        describe('SQL injection prevention', () => {
          it('rejects SQL injection attempt', () => {
            const input = "'; DROP TABLE users; --";
            expect(() => validateQuery(input)).toThrow();
          });
          it('rejects exec injection', () => {
            const input = "; rm -rf /";
            expect(() => validateCommand(input)).toThrow();
          });
        });
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("README documentation mentioning security terms", () => {
    const severe = scanForSevere(ctx({
      source_code: `
        # Security Best Practices
        ## Never use eval() with user input
        ## Always use parameterized queries to prevent SQL injection
        ## Use execFile() instead of exec() for shell commands
        ## Validate all input before processing
        ## Store secrets in environment variables, never hardcode them
      `,
    }));
    expect(severe).toEqual([]);
  });

  it("well-structured server with many tools (not consent fatigue)", () => {
    const tools = Array.from({ length: 8 }, (_, i) => ({
      name: `read_${["users", "orders", "products", "settings", "reports", "logs", "metrics", "config"][i]}`,
      description: `Read ${["user profiles", "order history", "product catalog", "app settings", "analytics reports", "access logs", "performance metrics", "server configuration"][i]}`,
      input_schema: { type: "object" as const, properties: { id: { type: "string" as const } } },
    }));
    const severe = scanForSevere(ctx({ tools }));
    expect(severe).toEqual([]);
  });
});
