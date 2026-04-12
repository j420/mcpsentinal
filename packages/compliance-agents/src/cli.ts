#!/usr/bin/env node
/**
 * compliance-scan CLI
 *
 * Usage:
 *   pnpm compliance-scan --server=<id> [--framework=<id>|all] [--use-llm-mock] [--mock-dir=<path>]
 *
 * The CLI builds an `AnalysisContext` for the requested server (using the
 * existing scanner pipeline stages 1–2 — wired in via the orchestrator's
 * caller), runs the orchestrator, and writes the report to stdout.
 *
 * NOTE: actual database integration lives in `packages/scanner` — this CLI
 * is the thin entry point that lets developers run the orchestrator
 * directly against a fixture context for development and CI smoke tests.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join as pathJoin, resolve as pathResolve } from "node:path";

import type { AnalysisContext } from "@mcp-sentinel/analyzer";

import { ComplianceOrchestrator } from "./orchestrator.js";
import { renderTextReport } from "./reporter.js";
import { InMemoryAuditLog } from "./llm/audit-log.js";
import { MockLLMClient, LiveLLMClient, type LLMClient } from "./llm/client.js";
import {
  ALL_FRAMEWORKS,
  type ComplianceScanRequest,
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

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (!args.contextFile) {
    process.stderr.write(
      "compliance-scan: --context=<path-to-analysis-context.json> is required for now.\n" +
        "  This CLI runs the orchestrator against a serialized AnalysisContext.\n" +
        "  Live DB-backed scanning will be wired through packages/scanner.\n",
    );
    return 2;
  }

  const contextPath = pathResolve(args.contextFile);
  const context = JSON.parse(readFileSync(contextPath, "utf8")) as AnalysisContext;
  if (args.server) {
    context.server.id = args.server;
  }

  const audit = new InMemoryAuditLog();
  let llm: LLMClient;
  if (args.useLLMMock) {
    const recordings = loadMockRecordings(args.mockDir);
    llm = new MockLLMClient(recordings, audit);
  } else {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      process.stderr.write(
        "compliance-scan: ANTHROPIC_API_KEY not set. Use --use-llm-mock for offline runs.\n",
      );
      return 2;
    }
    llm = new LiveLLMClient(apiKey, audit);
  }

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

  const result = await orchestrator.scan(context, request);
  process.stdout.write(renderTextReport(result));
  process.stdout.write("\n");

  // Exit non-zero if any framework reports non-compliant.
  const hasViolation = result.reports.some((r) => r.overall_status === "non-compliant");
  return hasViolation ? 1 : 0;
}

// Force ALL_FRAMEWORKS reference so import is preserved when tree-shaken.
void ALL_FRAMEWORKS;

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`compliance-scan failed: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
