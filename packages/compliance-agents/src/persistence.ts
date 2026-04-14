/**
 * Compliance persistence — the ONLY file in @mcp-sentinel/compliance-agents
 * that talks to the database. Keeps `orchestrator.ts` hermetic (still returns
 * in-memory `ComplianceScanResult`s), so unit tests remain DB-free.
 *
 * Two responsibilities:
 *
 *   1. `persistComplianceScanResult(...)` — writes a completed scan to DB:
 *      - every judge-confirmed finding → `compliance_findings` (one row per
 *        (framework, control) mapping in the finding's `applies_to` array,
 *        so queries can filter by framework without parsing JSONB)
 *      - every LLM audit event → `compliance_agent_runs` (prompt + response
 *        wrapped into the JSONB columns the schema expects)
 *
 *   2. `loadAnalysisContextFromDb(...)` — assembles an `AnalysisContext` from
 *      persisted DB state so the `compliance-scan --server=<slug-or-id>` CLI
 *      can run against a server without the caller hand-authoring a fixture
 *      JSON. Reuses data persisted by the regular `pnpm scan` pipeline
 *      (tools, dependencies, initialize metadata) — compliance runs after
 *      a normal scan and does NOT re-fetch source code from GitHub.
 *
 * Failure model: every single INSERT is wrapped in its own try/catch. A
 * partial failure (e.g. one bad finding) MUST NOT drop the rest of the
 * audit trail. Regulator replay is the non-negotiable contract of ADR-009,
 * so the persistence layer defaults to "record as much as possible, surface
 * errors in the return report, never throw".
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import type {
  ComplianceAgentRun,
  ComplianceFindingRecord,
  DatabaseQueries,
} from "@mcp-sentinel/database";

import type { LLMAuditEvent, LLMAuditLog } from "./llm/audit-log.js";
import type {
  ComplianceFinding,
  ComplianceScanResult,
  FrameworkControlMapping,
} from "./types.js";

// ─── persistComplianceScanResult ───────────────────────────────────────────

export interface PersistComplianceScanInput {
  db: DatabaseQueries;
  /** Scan id used to stamp both findings and audit rows */
  scanId: string;
  /** The in-memory result returned by `ComplianceOrchestrator.scan()` */
  result: ComplianceScanResult;
  /**
   * Audit log the orchestrator's LLMClient wrote to during the scan. MUST be
   * the same instance; `drain()` empties its buffer as a side-effect.
   */
  auditLog: LLMAuditLog;
  /** Optional structured logger — defaults to a silent no-op */
  logger?: PersistLogger;
}

export interface PersistLogger {
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
}

const SILENT_LOGGER: PersistLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

export interface PersistComplianceScanReport {
  scan_id: string;
  findings_persisted: number;
  finding_rows_persisted: number; // >= findings_persisted because of per-framework demux
  findings_failed: number;
  runs_persisted: number;
  runs_failed: number;
  errors: Array<{
    kind: "finding" | "run";
    ref: string;
    message: string;
  }>;
}

/**
 * Write a compliance scan result to the database.
 *
 * Preconditions:
 * - `result.combined_findings` contains only judge-confirmed findings
 *   (the orchestrator drops non-confirmed verdicts before reaching here).
 * - `auditLog` is the same instance shared with the orchestrator's LLMClient.
 *
 * Guarantees:
 * - No throw on per-row failure; the returned report enumerates failures.
 * - One `compliance_findings` row per (finding, framework mapping) pair so
 *   the `getComplianceFindingsForServer` query can WHERE by `framework`
 *   without parsing JSONB.
 * - Every drained audit event is written verbatim (prompt+response wrapped
 *   into JSONB) even if its finding sibling failed.
 */
export async function persistComplianceScanResult(
  input: PersistComplianceScanInput,
): Promise<PersistComplianceScanReport> {
  const logger = input.logger ?? SILENT_LOGGER;
  const report: PersistComplianceScanReport = {
    scan_id: input.scanId,
    findings_persisted: 0,
    finding_rows_persisted: 0,
    findings_failed: 0,
    runs_persisted: 0,
    runs_failed: 0,
    errors: [],
  };

  // ── Phase A: findings ──────────────────────────────────────────────────
  for (const finding of input.result.combined_findings) {
    const rowsForFinding = buildFindingRecords(input.scanId, finding);
    if (rowsForFinding.length === 0) {
      // A finding with no applies_to would be a bug in the rule — record it
      // so it's visible in the report, but do not throw.
      report.findings_failed += 1;
      report.errors.push({
        kind: "finding",
        ref: `${finding.rule_id}/${finding.test?.test_id ?? "<no-test>"}`,
        message: "Finding has zero applies_to mappings; nothing to persist",
      });
      logger.warn("compliance.persist: finding has no applies_to", {
        rule_id: finding.rule_id,
      });
      continue;
    }

    let anySucceeded = false;
    for (const record of rowsForFinding) {
      try {
        await input.db.insertComplianceFinding(record);
        report.finding_rows_persisted += 1;
        anySucceeded = true;
      } catch (err) {
        report.findings_failed += 1;
        report.errors.push({
          kind: "finding",
          ref: `${record.rule_id}@${record.framework}/${record.test_id}`,
          message: err instanceof Error ? err.message : String(err),
        });
        logger.error("compliance.persist: finding insert failed", {
          rule_id: record.rule_id,
          framework: record.framework,
          err: err instanceof Error ? err.message : String(err),
        });
      }
    }
    if (anySucceeded) report.findings_persisted += 1;
  }

  // ── Phase B: LLM audit events ──────────────────────────────────────────
  // Drain the buffer ONCE — losing events here would break the regulator
  // replay contract, so we wrap each insert in its own try/catch.
  const events = input.auditLog.drain();
  for (const event of events) {
    try {
      const row = buildAgentRunRecord(input.scanId, event);
      await input.db.insertComplianceAgentRun(row);
      report.runs_persisted += 1;
    } catch (err) {
      report.runs_failed += 1;
      report.errors.push({
        kind: "run",
        ref: `${event.rule_id}@${event.framework}/${event.phase}/${event.cache_key}`,
        message: err instanceof Error ? err.message : String(err),
      });
      logger.error("compliance.persist: agent run insert failed", {
        rule_id: event.rule_id,
        framework: event.framework,
        phase: event.phase,
        err: err instanceof Error ? err.message : String(err),
      });
    }
  }

  logger.info("compliance.persist: complete", {
    scan_id: input.scanId,
    findings_persisted: report.findings_persisted,
    finding_rows_persisted: report.finding_rows_persisted,
    findings_failed: report.findings_failed,
    runs_persisted: report.runs_persisted,
    runs_failed: report.runs_failed,
  });

  return report;
}

// ─── Internal: mapping helpers ─────────────────────────────────────────────

/**
 * Expand a `ComplianceFinding` into one `compliance_findings` row per
 * framework control it satisfies. The orchestrator stamps `applies_to`
 * from the rule's declared mappings, so a single rule that covers three
 * frameworks produces three rows with identical evidence but different
 * `framework` / `category_control` values. This is intentional: it lets
 * `getComplianceFindingsForServer(server, framework)` be a pure indexed
 * lookup rather than a JSONB unpacking exercise.
 */
function buildFindingRecords(
  scanId: string,
  finding: ComplianceFinding,
): Array<Omit<ComplianceFindingRecord, "id" | "created_at">> {
  const bundleId = extractBundleId(finding);
  const testId = finding.test?.test_id ?? `no-test-${finding.rule_id}`;
  const testHypothesis = finding.test?.hypothesis ?? "";
  const judgeRationale = finding.judge_result?.judge_rationale ?? "";
  const evidenceChain = finding.chain as unknown as Record<string, unknown>;
  const severity = finding.computed_severity?.effective ?? finding.severity;
  const confidence = typeof finding.confidence === "number" ? finding.confidence : 0;
  const remediation = finding.remediation ?? "";

  const rows: Array<Omit<ComplianceFindingRecord, "id" | "created_at">> = [];
  for (const mapping of finding.applies_to ?? []) {
    rows.push({
      scan_id: scanId,
      server_id: finding.server_id,
      framework: mapping.framework,
      rule_id: finding.rule_id,
      category_control: formatCategoryControl(mapping),
      severity,
      confidence,
      bundle_id: bundleId,
      test_id: testId,
      test_hypothesis: testHypothesis,
      judge_rationale: judgeRationale,
      evidence_chain: evidenceChain,
      remediation,
    });
  }
  return rows;
}

/**
 * Compose the human-readable category_control cell. Kept stable because it
 * is surfaced in compliance reports and API responses — changing the format
 * later would break any external consumer keying off it.
 */
function formatCategoryControl(mapping: FrameworkControlMapping): string {
  const base = `${mapping.category}|${mapping.control}`;
  return mapping.sub_control ? `${base}|${mapping.sub_control}` : base;
}

/**
 * The compliance-finding chain is built in `orchestrator.ts::buildFinding`
 * with `source.location = "bundle:<bundle_id>"`. Parse it back out so the
 * DB row carries the bundle id without the "bundle:" prefix. Falls back to
 * an empty string if the chain shape ever drifts, so the insert does not
 * hard-fail on a malformed chain.
 */
function extractBundleId(finding: ComplianceFinding): string {
  const chain = finding.chain as unknown as {
    source?: { location?: string };
  } | null;
  const loc = chain?.source?.location;
  if (typeof loc === "string" && loc.startsWith("bundle:")) {
    return loc.slice("bundle:".length);
  }
  // Fallback: anything that lets the regulator correlate by rule id.
  return `${finding.rule_id}:${finding.test?.test_id ?? "unknown"}`;
}

function buildAgentRunRecord(
  scanId: string,
  event: LLMAuditEvent,
): Omit<ComplianceAgentRun, "id" | "created_at"> {
  // `prompt` and `response` are JSONB columns; wrap the flat event strings
  // in envelope objects so downstream inspectors can key by field name.
  const prompt: Record<string, unknown> = {
    system: event.system,
    user: event.user,
  };
  const response: Record<string, unknown> = {
    text: event.response_text,
  };
  return {
    scan_id: scanId,
    server_id: event.server_id,
    rule_id: event.rule_id,
    framework: event.framework,
    phase: event.phase,
    cache_key: event.cache_key,
    model: event.model,
    temperature: event.temperature,
    max_tokens: event.max_tokens,
    prompt,
    response,
    cached: event.cached,
    duration_ms: event.duration_ms,
    input_tokens: event.input_tokens ?? null,
    output_tokens: event.output_tokens ?? null,
  };
}

// ─── loadAnalysisContextFromDb ─────────────────────────────────────────────

export interface LoadContextResult {
  context: AnalysisContext;
  /** Which structural pieces were available — surfaced in the CLI summary */
  coverage: {
    has_tools: boolean;
    has_dependencies: boolean;
    has_initialize_metadata: boolean;
    has_source_code: false; // compliance runs never refetch source (documented)
  };
}

/**
 * Resolve a server by UUID or slug and build an `AnalysisContext` from the
 * state persisted by the regular `pnpm scan` pipeline.
 *
 * Why not re-run Stage 1 (GitHub fetch) + Stage 2 (OSV audit)?
 *   - Source code: compliance rules operate on structural evidence (tools,
 *     schemas, annotations, initialize metadata). The few rules that need
 *     source code already use the analyzer infrastructure and will degrade
 *     gracefully to "insufficient evidence" rather than fire false positives
 *     when source is null. Re-fetching GitHub here would duplicate pipeline.ts
 *     logic and require a live network, which the CLI path must not assume.
 *   - Dependencies: already enriched by the most recent `pnpm scan` and
 *     stored in the `dependencies` table, so we read them as-is.
 *
 * Fields left intentionally empty (no DB source):
 *   - `source_code`, `source_files`: null/undefined — compliance runs do not
 *     refetch. Rules needing source are declared "degraded" in their charter.
 *   - `connection_metadata`: null — no live connection during compliance.
 *   - `resources`, `prompts`, `roots`, `declared_capabilities`: not currently
 *     persisted by `upsertTools()`. TODO once the connector persists them.
 *   - Tool `output_schema` and `annotations`: not persisted in the `tools`
 *     table today. Compliance rules that need annotations will correctly
 *     report "insufficient evidence" rather than hallucinate.
 */
export async function loadAnalysisContextFromDb(
  db: DatabaseQueries,
  serverIdOrSlug: string,
): Promise<LoadContextResult> {
  // Resolve server — try UUID first, then slug.
  let server = await safeGetServerById(db, serverIdOrSlug);
  if (!server) {
    server = await db.findServerBySlug(serverIdOrSlug);
  }
  if (!server) {
    throw new Error(
      `Server not found by id or slug: "${serverIdOrSlug}". ` +
        "Run `pnpm scan --server=<id>` first to populate DB state.",
    );
  }

  const [toolRows, depRows] = await Promise.all([
    db.getToolsForServer(server.id),
    db.getDependenciesForServer(server.id),
  ]);

  const tools: AnalysisContext["tools"] = toolRows.map((t) => ({
    name: t.name as string,
    description: (t.description as string | null) ?? null,
    input_schema:
      (t.input_schema as Record<string, unknown> | null) ?? null,
    output_schema: null,
    annotations: null,
  }));

  const dependencies: AnalysisContext["dependencies"] = depRows.map((d) => ({
    name: d.name,
    version: d.version,
    has_known_cve: d.has_known_cve,
    cve_ids: d.cve_ids,
    last_updated: d.last_updated,
  }));

  // H2 initialize_metadata: name is always on server.name; version and
  // instructions come from the connector snapshot persisted during scan.
  const serverVersion = server.server_version;
  const serverInstructions = server.server_instructions;
  const hasInitMeta = serverVersion !== null || serverInstructions !== null;

  const context: AnalysisContext = {
    server: {
      id: server.id,
      name: server.name,
      description: server.description ?? null,
      github_url: server.github_url ?? null,
    },
    tools,
    source_code: null,
    source_files: null,
    dependencies,
    connection_metadata: null,
    initialize_metadata: hasInitMeta
      ? {
          server_version: serverVersion,
          server_instructions: serverInstructions,
        }
      : undefined,
    resources: [],
    prompts: [],
    roots: [],
    declared_capabilities: null,
  };

  return {
    context,
    coverage: {
      has_tools: tools.length > 0,
      has_dependencies: dependencies.length > 0,
      has_initialize_metadata: hasInitMeta,
      has_source_code: false,
    },
  };
}

/**
 * `getServerById` throws on a non-UUID string because the query is typed
 * `WHERE id = $1::uuid`. The caller accepts either a UUID or a slug, so we
 * swallow the invalid-uuid error and let the slug branch try next.
 */
async function safeGetServerById(
  db: DatabaseQueries,
  candidate: string,
): Promise<Awaited<ReturnType<DatabaseQueries["getServerById"]>> | null> {
  if (!isLikelyUuid(candidate)) return null;
  try {
    return await db.getServerById(candidate);
  } catch {
    return null;
  }
}

function isLikelyUuid(value: string): boolean {
  // 8-4-4-4-12 hex groups. Avoid a full RFC validator — this is only used to
  // skip the UUID branch when the caller clearly passed a slug.
  return (
    value.length === 36 &&
    value[8] === "-" &&
    value[13] === "-" &&
    value[18] === "-" &&
    value[23] === "-"
  );
}
