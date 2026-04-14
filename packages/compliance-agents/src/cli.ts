#!/usr/bin/env node
/**
 * compliance-scan CLI
 *
 * Two run modes:
 *
 *   1. Fixture mode (developer / CI smoke path, unchanged):
 *        compliance-scan --context=<path-to-analysis-context.json> \
 *          [--framework=<id>|all] [--use-llm-mock] [--mock-dir=<path>]
 *
 *      Reads a serialized `AnalysisContext` from disk and runs the
 *      orchestrator against it. No DB touched. Used for `__tests__/` fixtures
 *      and quick local experiments.
 *
 *   2. DB-backed mode (production / ad-hoc regulator-replay path):
 *        compliance-scan --server=<slug-or-uuid> \
 *          [--framework=<id>|all] [--use-llm-mock] [--mock-dir=<path>]
 *
 *      - Opens a PostgreSQL pool from `DATABASE_URL`
 *      - Resolves the server by slug or UUID
 *      - Loads the `AnalysisContext` from state already persisted by the
 *        regular `pnpm scan` pipeline (tools + dependencies + initialize
 *        metadata). Source code is NOT refetched — compliance rules that
 *        need source already degrade gracefully to "insufficient evidence".
 *      - Creates an immutable row in `scans` (status='running') so the
 *        compliance persistence layer can stamp findings + audit rows with
 *        that scan_id.
 *      - Runs the orchestrator with the DB-managed scan_id threaded
 *        through via `request.scan_id` (so LLM audit events correlate).
 *      - Calls `persistComplianceScanResult()` to append findings rows
 *        (one per framework mapping) and drain the audit log into
 *        `compliance_agent_runs`. Every insert is individually try/caught
 *        — a single bad row cannot lose the rest of the audit trail.
 *      - Closes the DB scan with `completeScan()` carrying the total
 *        finding-row count and any aggregated error message.
 *      - Prints a summary report to stdout and exits non-zero if any
 *        framework reports non-compliant OR if persistence recorded
 *        per-row failures.
 *
 * `ANTHROPIC_API_KEY` is required unless `--use-llm-mock` is passed.
 * `DATABASE_URL` is required in DB-backed mode. Both modes default the
 * LLM client to `MockLLMClient` when `--use-llm-mock` is set; otherwise
 * `LiveLLMClient` talks to the real Anthropic API under ADR-009.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join as pathJoin, resolve as pathResolve } from "node:path";

import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import { DatabaseQueries } from "@mcp-sentinel/database";
import pg from "pg";

import { ComplianceOrchestrator } from "./orchestrator.js";
import { renderTextReport } from "./reporter.js";
import { InMemoryAuditLog } from "./llm/audit-log.js";
import { MockLLMClient, LiveLLMClient, type LLMClient } from "./llm/client.js";
import {
  loadAnalysisContextFromDb,
  persistComplianceScanResult,
  type PersistComplianceScanReport,
  type PersistLogger,
} from "./persistence.js";
import {
  ALL_FRAMEWORKS,
  type ComplianceScanRequest,
  type ComplianceScanResult,
  type FrameworkId,
} from "./types.js";

interface CliArgs {
  server?: string;
  framework: FrameworkId[] | "all";
  useLLMMock: boolean;
  mockDir: string;
  contextFile?: string;
  model?: string;
  maxTests: number;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    framework: "all",
    useLLMMock: false,
    mockDir: "__tests__/llm-mocks",
    maxTests: 5,
  };
  for (const raw of argv) {
    if (raw.startsWith("--server=")) args.server = raw.slice("--server=".length);
    else if (raw.startsWith("--framework=")) {
      const v = raw.slice("--framework=".length);
      if (v === "all") args.framework = "all";
      else args.framework = v.split(",") as FrameworkId[];
    } else if (raw === "--use-llm-mock") args.useLLMMock = true;
    else if (raw.startsWith("--mock-dir=")) args.mockDir = raw.slice("--mock-dir=".length);
    else if (raw.startsWith("--context=")) args.contextFile = raw.slice("--context=".length);
    else if (raw.startsWith("--model=")) args.model = raw.slice("--model=".length);
    else if (raw.startsWith("--max-tests=")) args.maxTests = Number(raw.slice("--max-tests=".length));
  }
  return args;
}

function loadMockRecordings(dir: string): Map<string, unknown> {
  const out = new Map<string, unknown>();
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  for (const name of entries) {
    if (!name.endsWith(".json")) continue;
    const full = pathJoin(dir, name);
    if (!statSync(full).isFile()) continue;
    const obj = JSON.parse(readFileSync(full, "utf8")) as { cache_key: string; response: unknown };
    out.set(obj.cache_key, obj.response);
  }
  return out;
}

/** Minimal structured logger that writes to stderr. Keeps persistence output
 *  visible in CI logs without pulling in pino as an extra hard dependency. */
const STDERR_LOGGER: PersistLogger = {
  info: (msg, ctx) =>
    process.stderr.write(`[compliance-scan] info  ${msg}${ctx ? " " + JSON.stringify(ctx) : ""}\n`),
  warn: (msg, ctx) =>
    process.stderr.write(`[compliance-scan] warn  ${msg}${ctx ? " " + JSON.stringify(ctx) : ""}\n`),
  error: (msg, ctx) =>
    process.stderr.write(`[compliance-scan] error ${msg}${ctx ? " " + JSON.stringify(ctx) : ""}\n`),
};

function buildLLMClient(
  useMock: boolean,
  mockDir: string,
  audit: InMemoryAuditLog,
): LLMClient {
  if (useMock) {
    const recordings = loadMockRecordings(mockDir);
    return new MockLLMClient(recordings, audit);
  }
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error(
      "ANTHROPIC_API_KEY not set. Use --use-llm-mock for offline runs.",
    );
  }
  return new LiveLLMClient(apiKey, audit);
}

/** Fixture mode: run orchestrator against a serialized AnalysisContext,
 *  no DB writes. Returns the orchestrator result for caller to render. */
async function runFixtureMode(args: CliArgs): Promise<ComplianceScanResult> {
  const contextPath = pathResolve(args.contextFile!);
  const context = JSON.parse(readFileSync(contextPath, "utf8")) as AnalysisContext;
  if (args.server) context.server.id = args.server;

  const audit = new InMemoryAuditLog();
  const llm = buildLLMClient(args.useLLMMock, args.mockDir, audit);

  const orchestrator = new ComplianceOrchestrator({
    llm,
    audit,
    model: args.model,
  });

  const request: ComplianceScanRequest = {
    server_id: context.server.id,
    frameworks: args.framework,
    use_llm_mock: args.useLLMMock,
    model: args.model,
    max_tests_per_rule: args.maxTests,
  };

  return orchestrator.scan(context, request);
}

/**
 * DB-backed mode: load context from persisted scan state, create an
 * immutable scan row, run the orchestrator with that scan_id, persist
 * findings + audit events, close the scan. Returns the orchestrator
 * result plus the persistence report so the caller can surface per-row
 * failures.
 */
async function runDbMode(args: CliArgs): Promise<{
  result: ComplianceScanResult;
  persist: PersistComplianceScanReport;
}> {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error(
      "DATABASE_URL environment variable is required for --server mode. " +
        "Use --context=<file.json> for fixture-driven runs.",
    );
  }

  const pool = new pg.Pool({ connectionString: databaseUrl });
  pool.on("error", (err: Error) => {
    process.stderr.write(
      `[compliance-scan] warn  pool error: ${err.message}\n`,
    );
  });

  const db = new DatabaseQueries(pool);
  try {
    // Stage 1: resolve server + load context from DB
    const { context, coverage } = await loadAnalysisContextFromDb(db, args.server!);
    STDERR_LOGGER.info("context loaded from DB", {
      server_id: context.server.id,
      tools: context.tools.length,
      dependencies: context.dependencies.length,
      has_tools: coverage.has_tools,
      has_dependencies: coverage.has_dependencies,
      has_initialize_metadata: coverage.has_initialize_metadata,
    });

    // Stage 2: open a scan row so every finding + audit event gets the same id
    const scanId = await db.createScan(context.server.id, "compliance-agents");
    STDERR_LOGGER.info("scan row created", { scan_id: scanId });

    // Stage 3: run the orchestrator under the DB-managed scan id
    const audit = new InMemoryAuditLog();
    const llm = buildLLMClient(args.useLLMMock, args.mockDir, audit);
    const orchestrator = new ComplianceOrchestrator({
      llm,
      audit,
      model: args.model,
    });

    const request: ComplianceScanRequest = {
      server_id: context.server.id,
      frameworks: args.framework,
      use_llm_mock: args.useLLMMock,
      model: args.model,
      max_tests_per_rule: args.maxTests,
      scan_id: scanId,
    };

    let result: ComplianceScanResult;
    let runError: string | null = null;
    try {
      result = await orchestrator.scan(context, request);
    } catch (err) {
      runError = err instanceof Error ? err.message : String(err);
      // Close the scan row with a failure marker and rethrow so the CLI
      // exit code reflects the crash.
      await db.completeScan(scanId, 0, runError);
      throw err;
    }

    // Stage 4: persist findings + audit events. Never throws per-row.
    const persist = await persistComplianceScanResult({
      db,
      scanId,
      result,
      auditLog: audit,
      logger: STDERR_LOGGER,
    });

    // Stage 5: close the scan row. Stages-column usage mirrors the regular
    // scanner pipeline so the scans list is shape-consistent.
    const failureSummary =
      persist.errors.length > 0
        ? `persistence: ${persist.findings_failed} finding failures, ${persist.runs_failed} run failures`
        : null;
    await db.completeScan(scanId, persist.finding_rows_persisted, failureSummary, {
      source_fetched: false,
      connection_attempted: false,
      connection_succeeded: false,
      dependencies_audited: coverage.has_dependencies,
    });

    return { result, persist };
  } finally {
    await pool.end();
  }
}

function printPersistSummary(report: PersistComplianceScanReport): void {
  process.stderr.write(
    `[compliance-scan] persist  scan=${report.scan_id} ` +
      `findings=${report.findings_persisted} rows=${report.finding_rows_persisted} ` +
      `findings_failed=${report.findings_failed} runs=${report.runs_persisted} ` +
      `runs_failed=${report.runs_failed}\n`,
  );
  if (report.errors.length > 0) {
    process.stderr.write(
      `[compliance-scan] persist  ${report.errors.length} per-row failure(s):\n`,
    );
    for (const e of report.errors.slice(0, 10)) {
      process.stderr.write(`    [${e.kind}] ${e.ref}: ${e.message}\n`);
    }
    if (report.errors.length > 10) {
      process.stderr.write(`    ... (${report.errors.length - 10} more)\n`);
    }
  }
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  const useDbMode = Boolean(args.server) && !args.contextFile;

  if (!args.contextFile && !args.server) {
    process.stderr.write(
      "compliance-scan: either --server=<slug-or-uuid> (DB-backed) or " +
        "--context=<file.json> (fixture) is required.\n",
    );
    return 2;
  }

  let result: ComplianceScanResult;
  let persist: PersistComplianceScanReport | null = null;

  if (useDbMode) {
    const out = await runDbMode(args);
    result = out.result;
    persist = out.persist;
  } else {
    result = await runFixtureMode(args);
  }

  process.stdout.write(renderTextReport(result));
  process.stdout.write("\n");

  if (persist) printPersistSummary(persist);

  const hasViolation = result.reports.some((r) => r.overall_status === "non-compliant");
  const persistenceFailed = persist ? persist.errors.length > 0 : false;
  return hasViolation || persistenceFailed ? 1 : 0;
}

// Force ALL_FRAMEWORKS reference so import is preserved when tree-shaken.
void ALL_FRAMEWORKS;

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(
      `compliance-scan failed: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exit(1);
  });
