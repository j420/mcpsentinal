#!/usr/bin/env node
/**
 * MCP Sentinel — MCP Server
 *
 * An MCP server that exposes security scanning as tools.
 * Clients can submit server metadata (tools, descriptions, source code)
 * and receive security findings + a composite score.
 *
 * Tools:
 *   scan_server   — Analyze server metadata (tools, source code, dependencies)
 *   scan_endpoint — Connect to a live MCP endpoint, enumerate, then analyze
 *   list_rules    — List all 177 detection rules with severity and category
 *
 * Safety: This server NEVER invokes tools on scanned servers (ADR-007).
 *         It only calls initialize + tools/list for enumeration.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { AnalysisEngine, loadRules, type AnalysisContext } from "@mcp-sentinel/analyzer";
import { computeScore, type ScoreResult } from "@mcp-sentinel/scorer";
import { MCPConnector } from "@mcp-sentinel/connector";
import type { DetectionRule, FindingInput } from "@mcp-sentinel/database";
import { z } from "zod";
import { readdirSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import pino from "pino";

const logger = pino({ name: "mcp-sentinel-scanner" }, process.stderr);

// ── Resolve rules directory ──────────────────────────────────────────────────

function findRulesDir(): string {
  const thisDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(thisDir, "..", "..", "..", "rules"),
    join(thisDir, "..", "rules"),
    join(process.cwd(), "rules"),
  ];
  for (const dir of candidates) {
    try {
      if (readdirSync(dir).some(f => f.endsWith(".yaml"))) return dir;
    } catch { /* skip */ }
  }
  return join(process.cwd(), "rules");
}

// ── Input validation schemas ─────────────────────────────────────────────────

const ToolSchema = z.object({
  name: z.string(),
  description: z.string().nullable().default(null),
  input_schema: z.record(z.unknown()).nullable().default(null),
  output_schema: z.record(z.unknown()).nullable().optional(),
  annotations: z.object({
    readOnlyHint: z.boolean().optional(),
    destructiveHint: z.boolean().optional(),
    idempotentHint: z.boolean().optional(),
    openWorldHint: z.boolean().optional(),
  }).nullable().optional(),
});

const DependencySchema = z.object({
  name: z.string(),
  version: z.string().nullable().default(null),
  has_known_cve: z.boolean().default(false),
  cve_ids: z.array(z.string()).default([]),
  last_updated: z.string().nullable().default(null),
});

const ScanServerInputSchema = z.object({
  server_name: z.string().describe("Name of the MCP server to analyze"),
  server_description: z.string().nullable().default(null).describe("Server description"),
  tools: z.array(ToolSchema).default([]).describe("Array of tools exposed by the server"),
  source_code: z.string().nullable().default(null).describe("Concatenated source code (optional, enables code analysis rules C1-C16)"),
  dependencies: z.array(DependencySchema).default([]).describe("Package dependencies (optional, enables dependency rules D1-D7)"),
  github_url: z.string().nullable().default(null).describe("GitHub repository URL (optional)"),
  server_version: z.string().nullable().default(null).describe("Server version from initialize response"),
  server_instructions: z.string().nullable().default(null).describe("Server instructions from initialize response"),
});

const ScanEndpointInputSchema = z.object({
  endpoint_url: z.string().url().describe("HTTP(S) URL of the MCP server endpoint"),
  server_name: z.string().default("unknown").describe("Name to use for this server in the report"),
  timeout_ms: z.number().min(1000).max(60000).default(30000).describe("Connection timeout in milliseconds"),
  source_code: z.string().nullable().default(null).describe("Optional source code for deeper analysis"),
  dependencies: z.array(DependencySchema).default([]).describe("Optional dependencies for CVE checks"),
});

const ListRulesInputSchema = z.object({
  category: z.string().optional().describe("Filter by category (e.g., 'code-analysis', 'description-analysis')"),
  severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional().describe("Filter by severity"),
});

// ── Result formatting ────────────────────────────────────────────────────────

interface ScanResult {
  server_name: string;
  total_score: number;
  rating: string;
  findings_count: number;
  findings: FindingInput[];
  score_breakdown: ScoreResult;
  rules_version: string;
}

function formatResult(
  serverName: string,
  findings: FindingInput[],
  score: ScoreResult,
  rulesVersion: string,
): ScanResult {
  const rating = score.total_score >= 80 ? "Good" :
                 score.total_score >= 60 ? "Moderate" :
                 score.total_score >= 40 ? "Poor" : "Critical";
  return {
    server_name: serverName,
    total_score: score.total_score,
    rating,
    findings_count: findings.length,
    findings,
    score_breakdown: score,
    rules_version: rulesVersion,
  };
}

// ── Main server ──────────────────────────────────────────────────────────────

async function main() {
  const rulesDir = findRulesDir();
  logger.info({ rulesDir }, "Loading detection rules");

  let rules: DetectionRule[];
  try {
    rules = loadRules(rulesDir);
  } catch (err) {
    logger.error({ err, rulesDir }, "Failed to load rules — starting with empty ruleset");
    rules = [];
  }

  const engine = new AnalysisEngine(rules);
  const rulesVersion = `${rules.length} rules`;

  // Build rule category map for scorer
  const ruleCategories: Record<string, string> = {};
  for (const rule of rules) {
    ruleCategories[rule.id] = rule.category;
  }

  logger.info({ ruleCount: rules.length }, "MCP Sentinel Scanner starting");

  const server = new Server(
    { name: "mcp-sentinel-scanner", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  // ── List tools ──────────────────────────────────────────

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: "scan_server",
        description: "Analyze an MCP server's security posture from its metadata (tools, descriptions, source code, dependencies). Returns findings and a 0-100 score across 177 detection rules covering prompt injection, command injection, data exfiltration, supply chain attacks, and more.",
        inputSchema: {
          type: "object" as const,
          properties: {
            server_name: { type: "string", description: "Name of the MCP server" },
            server_description: { type: "string", description: "Server description (nullable)" },
            tools: {
              type: "array",
              description: "Tools exposed by the server",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  description: { type: "string" },
                  input_schema: { type: "object" },
                },
                required: ["name"],
              },
            },
            source_code: { type: "string", description: "Concatenated source code for code analysis (C1-C16 rules)" },
            dependencies: {
              type: "array",
              description: "Package dependencies for CVE checks (D1-D7 rules)",
              items: {
                type: "object",
                properties: {
                  name: { type: "string" },
                  version: { type: "string" },
                  has_known_cve: { type: "boolean" },
                  cve_ids: { type: "array", items: { type: "string" } },
                },
                required: ["name"],
              },
            },
            github_url: { type: "string", description: "GitHub repo URL" },
            server_version: { type: "string", description: "Version from initialize handshake" },
            server_instructions: { type: "string", description: "Instructions from initialize handshake" },
          },
          required: ["server_name"],
        },
      },
      {
        name: "scan_endpoint",
        description: "Connect to a live MCP server endpoint, enumerate its tools via initialize + tools/list (safe, read-only), then run all 177 detection rules. Returns findings and score. Never invokes any tools on the target server.",
        inputSchema: {
          type: "object" as const,
          properties: {
            endpoint_url: { type: "string", description: "HTTP(S) URL of the MCP server" },
            server_name: { type: "string", description: "Label for this server in the report" },
            timeout_ms: { type: "number", description: "Connection timeout (1000-60000ms, default 30000)" },
            source_code: { type: "string", description: "Optional source code for deeper analysis" },
            dependencies: {
              type: "array",
              description: "Optional dependencies",
              items: {
                type: "object",
                properties: { name: { type: "string" }, version: { type: "string" } },
                required: ["name"],
              },
            },
          },
          required: ["endpoint_url"],
        },
      },
      {
        name: "list_rules",
        description: "List all available detection rules. Can filter by category or severity.",
        inputSchema: {
          type: "object" as const,
          properties: {
            category: { type: "string", description: "Filter by category (e.g., code-analysis, description-analysis)" },
            severity: { type: "string", enum: ["critical", "high", "medium", "low", "informational"], description: "Filter by severity" },
          },
        },
      },
    ],
  }));

  // ── Handle tool calls ───────────────────────────────────

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case "scan_server": {
          const input = ScanServerInputSchema.parse(args);
          const context: AnalysisContext = {
            server: {
              id: "mcp-scan-" + Date.now(),
              name: input.server_name,
              description: input.server_description,
              github_url: input.github_url,
            },
            tools: input.tools.map(t => ({
              name: t.name,
              description: t.description,
              input_schema: t.input_schema,
              output_schema: t.output_schema ?? null,
              annotations: t.annotations ?? null,
            })),
            source_code: input.source_code,
            dependencies: input.dependencies.map(d => ({
              ...d,
              last_updated: d.last_updated ? new Date(d.last_updated) : null,
            })),
            connection_metadata: null,
            initialize_metadata: {
              server_version: input.server_version,
              server_instructions: input.server_instructions,
            },
          };

          const findings = engine.analyze(context);
          const score = computeScore(findings, ruleCategories);
          const result = formatResult(input.server_name, findings, score, rulesVersion);

          logger.info({
            server: input.server_name,
            score: score.total_score,
            findings: findings.length,
          }, "Scan complete");

          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify(result, null, 2),
            }],
          };
        }

        case "scan_endpoint": {
          const input = ScanEndpointInputSchema.parse(args);
          const connector = new MCPConnector({ timeout: input.timeout_ms });

          logger.info({ endpoint: input.endpoint_url }, "Connecting to MCP endpoint");

          const serverId = "mcp-live-" + Date.now();
          const enumeration = await connector.enumerate(serverId, input.endpoint_url);

          if (!enumeration.connection_success) {
            return {
              content: [{
                type: "text" as const,
                text: JSON.stringify({
                  error: "Connection failed",
                  detail: enumeration.connection_error,
                  endpoint: input.endpoint_url,
                }, null, 2),
              }],
              isError: true,
            };
          }

          const context: AnalysisContext = {
            server: {
              id: serverId,
              name: input.server_name,
              description: null,
              github_url: null,
            },
            tools: enumeration.tools.map(t => ({
              name: t.name,
              description: t.description ?? null,
              input_schema: (t.input_schema as Record<string, unknown>) ?? null,
              output_schema: (t.output_schema as Record<string, unknown>) ?? null,
              annotations: t.annotations ? {
                readOnlyHint: (t.annotations as Record<string, boolean>).readOnlyHint,
                destructiveHint: (t.annotations as Record<string, boolean>).destructiveHint,
                idempotentHint: (t.annotations as Record<string, boolean>).idempotentHint,
                openWorldHint: (t.annotations as Record<string, boolean>).openWorldHint,
              } : null,
            })),
            source_code: input.source_code,
            dependencies: input.dependencies.map(d => ({
              ...d,
              last_updated: d.last_updated ? new Date(d.last_updated) : null,
            })),
            connection_metadata: {
              auth_required: false,
              transport: input.endpoint_url.includes("/sse") ? "sse" : "streamable-http",
              response_time_ms: enumeration.response_time_ms,
            },
            initialize_metadata: {
              server_version: enumeration.server_version ?? null,
              server_instructions: enumeration.server_instructions ?? null,
            },
            resources: enumeration.resources?.map(r => ({
              uri: r.uri,
              name: r.name,
              description: (r as unknown as Record<string, string | null>).description ?? null,
              mimeType: (r as unknown as Record<string, string | null>).mimeType ?? null,
            })),
            prompts: enumeration.prompts?.map(p => ({
              name: p.name,
              description: (p as unknown as Record<string, string | null>).description ?? null,
              arguments: ((p as unknown as Record<string, unknown>).arguments as Array<{name: string; description?: string; required?: boolean}>) ?? [],
            })),
            declared_capabilities: enumeration.declared_capabilities,
          };

          const findings = engine.analyze(context);
          const score = computeScore(findings, ruleCategories);
          const result = formatResult(input.server_name, findings, score, rulesVersion);

          // Add connection info to the result
          const enrichedResult = {
            ...result,
            connection: {
              endpoint: input.endpoint_url,
              tools_enumerated: enumeration.tools.length,
              response_time_ms: enumeration.response_time_ms,
              server_version: enumeration.server_version,
              transport: input.endpoint_url.includes("/sse") ? "sse" : "streamable-http",
            },
          };

          logger.info({
            endpoint: input.endpoint_url,
            tools: enumeration.tools.length,
            score: score.total_score,
            findings: findings.length,
          }, "Live scan complete");

          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify(enrichedResult, null, 2),
            }],
          };
        }

        case "list_rules": {
          const input = ListRulesInputSchema.parse(args ?? {});
          let filtered = rules;
          if (input.category) {
            filtered = filtered.filter(r => r.category === input.category);
          }
          if (input.severity) {
            filtered = filtered.filter(r => r.severity === input.severity);
          }

          const ruleList = filtered.map(r => ({
            id: r.id,
            name: r.name,
            category: r.category,
            severity: r.severity,
            owasp: r.owasp ?? null,
            mitre: r.mitre ?? null,
            remediation: r.remediation,
          }));

          return {
            content: [{
              type: "text" as const,
              text: JSON.stringify({
                total: ruleList.length,
                rules: ruleList,
              }, null, 2),
            }],
          };
        }

        default:
          return {
            content: [{ type: "text" as const, text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (err) {
      const message = err instanceof z.ZodError
        ? `Validation error: ${err.errors.map(e => `${e.path.join(".")}: ${e.message}`).join(", ")}`
        : err instanceof Error
        ? err.message
        : "Unknown error";

      logger.error({ tool: name, err }, "Tool call failed");

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ error: message }, null, 2) }],
        isError: true,
      };
    }
  });

  // ── Start server ────────────────────────────────────────

  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("MCP Sentinel Scanner running on stdio");
}

main().catch((err) => {
  logger.fatal({ err }, "Failed to start MCP Sentinel Scanner");
  process.exit(1);
});
