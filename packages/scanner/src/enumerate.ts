#!/usr/bin/env node
/**
 * Lightweight enumerate-only pipeline.
 *
 * Runs ONLY stages 3+4 of the scan pipeline:
 *   Stage 3: discoverEndpoint()   — find live HTTP endpoint from sources metadata
 *   Stage 4: MCPConnector         — enumerate tools via initialize + tools/list
 *
 * Populates tool_count + connection_status on every server without running
 * source fetch, dependency audit, analysis, or scoring.
 *
 * Usage:
 *   pnpm enumerate                        Enumerate all un-enumerated servers
 *   pnpm enumerate --limit=500            Process up to 500 servers
 *   pnpm enumerate --concurrency=10       10 parallel connections
 *   pnpm enumerate --all                  Re-enumerate all servers (including already enumerated)
 *   pnpm enumerate --json                 JSON output
 */

import { parseArgs } from "node:util";
import process from "node:process";
import pg from "pg";
import pino from "pino";
import { DatabaseQueries } from "@mcp-sentinel/database";
import type { Server } from "@mcp-sentinel/database";
import { MCPConnector } from "@mcp-sentinel/connector";

const logger = pino({ name: "scanner:enumerate" });

const DEFAULT_CONCURRENCY = 10;
const DEFAULT_LIMIT = 500;

interface EnumerateResult {
  server_id: string;
  server_name: string;
  endpoint: string | null;
  tool_count: number;
  connection_status: "success" | "failed" | "timeout" | "no_endpoint";
  elapsed_ms: number;
  error: string | null;
}

// ── Endpoint discovery (extracted from ScanPipeline) ─────────────────────────

function isHttpUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Filter out known non-MCP URLs (registry listing pages, GitHub, npm, PyPI).
 * These return HTML, not MCP protocol responses.
 */
function isMcpEndpoint(url: string): boolean {
  try {
    const host = new URL(url).hostname.toLowerCase();
    const nonMcpHosts = [
      "pulsemcp.com", "www.pulsemcp.com",
      "smithery.ai", "www.smithery.ai", "registry.smithery.ai",
      "github.com", "www.github.com",
      "npmjs.com", "www.npmjs.com",
      "pypi.org", "www.pypi.org",
      "registry.modelcontextprotocol.io",
      "glama.ai", "www.glama.ai",
    ];
    return !nonMcpHosts.includes(host);
  } catch {
    return false;
  }
}

async function discoverEndpoint(
  db: DatabaseQueries,
  server: Server
): Promise<string | null> {
  // Check cached endpoint first
  if (server.endpoint_url && isHttpUrl(server.endpoint_url)) {
    return server.endpoint_url;
  }

  try {
    const sources = await db.getServerSources(server.id);

    for (const source of sources) {
      const meta = source.raw_metadata as Record<string, unknown>;

      for (const field of [
        "endpoint",
        "server_url",
        "url",
        "endpoint_url",
        "baseUrl",
        "base_url",
        "serverUrl",
      ]) {
        const value = meta[field];
        if (typeof value === "string" && isHttpUrl(value) && isMcpEndpoint(value)) {
          return value;
        }
      }

      // Smithery: qualifiedName → construct official Smithery endpoint
      if (
        source.source_name === "smithery" &&
        typeof meta.qualifiedName === "string" &&
        meta.qualifiedName.trim()
      ) {
        return `https://server.smithery.ai/${meta.qualifiedName}/mcp`;
      }
    }
  } catch (err) {
    logger.warn(
      { server_id: server.id, err },
      "Endpoint discovery error"
    );
  }

  return null;
}

// ── Semaphore for concurrency control ────────────────────────────────────────

class Semaphore {
  private queue: Array<() => void> = [];
  private active = 0;

  constructor(private max: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.queue.shift()?.();
    }
  }
}

// ── Enumerate one server ─────────────────────────────────────────────────────

async function enumerateOne(
  db: DatabaseQueries,
  connector: MCPConnector,
  server: Server
): Promise<EnumerateResult> {
  const start = Date.now();
  const shortId = server.id.substring(0, 8);

  const endpoint = await discoverEndpoint(db, server);

  if (!endpoint) {
    await db.updateServerConnectionData(server.id, {
      connection_status: "no_endpoint",
    });

    return {
      server_id: server.id,
      server_name: server.name,
      endpoint: null,
      tool_count: 0,
      connection_status: "no_endpoint",
      elapsed_ms: Date.now() - start,
      error: null,
    };
  }

  try {
    const enumeration = await connector.enumerate(server.id, endpoint);

    if (enumeration.connection_success) {
      await db.upsertTools(server.id, enumeration.tools);
      await db.updateServerConnectionData(server.id, {
        endpoint_url: endpoint,
        connection_status: "success",
        server_version: enumeration.server_version ?? null,
        server_instructions: enumeration.server_instructions ?? null,
      });

      logger.info(
        { shortId, name: server.name, tools: enumeration.tools.length },
        "Enumerated"
      );

      return {
        server_id: server.id,
        server_name: server.name,
        endpoint,
        tool_count: enumeration.tools.length,
        connection_status: "success",
        elapsed_ms: Date.now() - start,
        error: null,
      };
    }

    const status = enumeration.connection_error?.includes("timeout")
      ? ("timeout" as const)
      : ("failed" as const);

    await db.updateServerConnectionData(server.id, {
      endpoint_url: endpoint,
      connection_status: status,
    });

    return {
      server_id: server.id,
      server_name: server.name,
      endpoint,
      tool_count: 0,
      connection_status: status,
      elapsed_ms: Date.now() - start,
      error: enumeration.connection_error,
    };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);

    await db.updateServerConnectionData(server.id, {
      endpoint_url: endpoint,
      connection_status: "failed",
    });

    return {
      server_id: server.id,
      server_name: server.name,
      endpoint,
      tool_count: 0,
      connection_status: "failed",
      elapsed_ms: Date.now() - start,
      error: errorMsg,
    };
  }
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      concurrency: { type: "string", default: String(DEFAULT_CONCURRENCY) },
      limit: { type: "string", default: String(DEFAULT_LIMIT) },
      all: { type: "boolean", default: false },
      json: { type: "boolean", default: false },
    },
    strict: true,
  });

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    logger.error("DATABASE_URL environment variable is required");
    process.exit(1);
  }

  const concurrency = parseInt(values.concurrency ?? String(DEFAULT_CONCURRENCY), 10);
  const limit = parseInt(values.limit ?? String(DEFAULT_LIMIT), 10);

  const pool = new pg.Pool({ connectionString: databaseUrl });
  const db = new DatabaseQueries(pool);
  const connector = new MCPConnector({ timeout: 30_000 });

  try {
    const servers: Server[] = values.all
      ? await db.getAllServers(limit)
      : await db.getServersNeedingEnumeration(limit);

    logger.info(
      { count: servers.length, mode: values.all ? "all" : "unenumerated", concurrency },
      "Enumerate pipeline starting"
    );

    if (servers.length === 0) {
      logger.info("No servers to enumerate");
      if (values.json) process.stdout.write("[]\n");
      return;
    }

    const semaphore = new Semaphore(concurrency);
    const runStart = Date.now();

    const results = await Promise.all(
      servers.map((server) =>
        semaphore.run(() => enumerateOne(db, connector, server))
      )
    );

    const elapsed = ((Date.now() - runStart) / 1000).toFixed(1);
    const connected = results.filter((r) => r.connection_status === "success").length;
    const noEndpoint = results.filter((r) => r.connection_status === "no_endpoint").length;
    const failed = results.filter(
      (r) => r.connection_status === "failed" || r.connection_status === "timeout"
    ).length;
    const totalTools = results.reduce((s, r) => s + r.tool_count, 0);

    if (values.json) {
      process.stdout.write(JSON.stringify({ results, summary: { total: results.length, connected, no_endpoint: noEndpoint, failed, total_tools: totalTools, elapsed_s: parseFloat(elapsed) } }, null, 2) + "\n");
    } else {
      const bar = "─".repeat(58);
      console.log(`\n${bar}`);
      console.log("  MCP SENTINEL — Enumerate Pipeline Complete");
      console.log(bar);
      console.log(`  Servers processed : ${results.length}`);
      console.log(`  Connected         : ${connected}`);
      console.log(`  No endpoint       : ${noEndpoint}`);
      console.log(`  Failed/Timeout    : ${failed}`);
      console.log(`  Total tools found : ${totalTools}`);
      console.log(`  Elapsed           : ${elapsed}s`);
      console.log(bar);

      if (results.length <= 50) {
        console.log(`\n  ${"Server".padEnd(40)} ${"Tools".padEnd(8)} ${"Status".padEnd(14)} Time`);
        console.log("  " + "─".repeat(70));
        for (const r of results) {
          const name = r.server_name.substring(0, 38).padEnd(40);
          const tools = String(r.tool_count).padEnd(8);
          const status = r.connection_status.padEnd(14);
          const time = `${(r.elapsed_ms / 1000).toFixed(1)}s`;
          console.log(`  ${name} ${tools} ${status} ${time}`);
        }
      }

      console.log(`\n${bar}\n`);
    }

    process.exitCode = connected === 0 && results.length > 0 ? 1 : 0;
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error({ err }, "Fatal enumerate error");
  process.exit(1);
});
