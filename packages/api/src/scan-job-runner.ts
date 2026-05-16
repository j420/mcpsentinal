/**
 * P21 — Public Scan Surface Engineer
 * scan-job-runner.ts — runs ad-hoc scan jobs in-process and registers
 * successful results in the public registry.
 *
 * The API is the only always-on service (there are no workers), so the
 * job runs as a background task inside the API process. `POST /api/v1/scan`
 * enqueues a job and returns 202 immediately; this runner drains the queue.
 *
 * Concurrency is capped (MAX_CONCURRENT) so a burst of expensive source
 * scans cannot exhaust the process. Jobs orphaned by a process restart are
 * recovered by `sweepStaleRunningJobs()` at startup.
 *
 * The heavy `@mcp-sentinel/scanner` module (which transitively loads the
 * analyzer + all 164 rules) is lazy-imported on first use so it does not
 * inflate API boot time.
 */

import pino from "pino";
import type { DatabaseQueries, FindingInput } from "@mcp-sentinel/database";
import type {
  AdHocScanInput,
  AdHocScanResult,
  ScannedServer,
} from "@mcp-sentinel/scanner";

const logger = pino({ name: "api:scan-job-runner" }, process.stderr);

/** Max scan jobs running at once. Excess jobs wait in the in-process queue. */
const MAX_CONCURRENT = 3;

interface QueuedJob {
  jobId: string;
  input: AdHocScanInput;
}

export class ScanJobRunner {
  private active = 0;
  private readonly queue: QueuedJob[] = [];

  constructor(private readonly db: DatabaseQueries) {}

  /** Enqueue a job. Returns immediately; the job runs in the background. */
  enqueue(jobId: string, input: AdHocScanInput): void {
    this.queue.push({ jobId, input });
    this.drain();
  }

  private drain(): void {
    while (this.active < MAX_CONCURRENT && this.queue.length > 0) {
      const next = this.queue.shift();
      if (!next) break;
      this.active++;
      // Fire-and-forget — the runner owns all error handling internally.
      void this.runJob(next.jobId, next.input).finally(() => {
        this.active--;
        this.drain();
      });
    }
  }

  private async runJob(jobId: string, input: AdHocScanInput): Promise<void> {
    try {
      await this.db.markScanJobRunning(jobId);
    } catch (err) {
      logger.error({ jobId, err }, "Failed to mark job running");
      return;
    }

    let result: AdHocScanResult;
    try {
      // Lazy import — keeps the analyzer + 164 rules out of API boot.
      const scanner = await import("@mcp-sentinel/scanner");
      result = await scanner.runAdHocScan(input);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "The scan failed unexpectedly.";
      logger.warn({ jobId, err: message }, "Ad-hoc scan failed");
      await this.safeFail(jobId, message);
      return;
    }

    // Register every scanned server in the public registry. A per-server
    // failure does not fail the job — the others still register.
    const registeredSlugs: string[] = [];
    const serversForResult: Array<Record<string, unknown>> = [];

    for (const server of result.servers) {
      const registrable =
        result.input_type === "source" || server.connection_success;
      let slug: string | null = null;
      if (registrable) {
        try {
          slug = await this.registerServer(server, result);
          registeredSlugs.push(slug);
        } catch (err) {
          logger.warn(
            { jobId, server: server.name, err },
            "Failed to register scanned server — continuing",
          );
        }
      }
      serversForResult.push({ ...server, registered_slug: slug });
    }

    const coverageBand =
      result.servers[0]?.coverage.confidence_band ?? null;

    try {
      await this.db.completeScanJob(
        jobId,
        { ...result, servers: serversForResult },
        coverageBand,
        registeredSlugs,
      );
      logger.info(
        { jobId, registered: registeredSlugs.length },
        "Ad-hoc scan job complete",
      );
    } catch (err) {
      logger.error({ jobId, err }, "Failed to persist completed job");
      await this.safeFail(jobId, "The scan finished but the result could not be saved.");
    }
  }

  /**
   * Create a fresh registry entry for one scanned server and persist its
   * scan + findings + score. Returns the new server slug.
   */
  private async registerServer(
    server: ScannedServer,
    result: AdHocScanResult,
  ): Promise<string> {
    const connectionStatus = server.connection_success
      ? "success"
      : server.endpoint
        ? "failed"
        : null;

    const { server_id, slug } = await this.db.createSelfSubmittedServer({
      name: server.name,
      description: `Added via the ad-hoc scanner (${result.input_type} scan).`,
      category: null,
      language: null,
      endpoint_url: server.endpoint,
      connection_status: connectionStatus,
      raw_identity: {
        scanned_via: result.input_type,
        endpoint: server.endpoint,
        github_url: server.github_url,
        npm_package: server.npm_package,
        pypi_package: server.pypi_package,
        rules_version: result.rules_version,
        scanned_at: new Date().toISOString(),
      },
    });

    if (server.tools.length > 0) {
      await this.db.upsertTools(server_id, server.tools);
    }

    const scanId = await this.db.createScan(server_id, result.rules_version);

    const findings: FindingInput[] = server.findings.map((f) => ({
      rule_id: f.rule_id,
      severity: f.severity,
      evidence: f.evidence,
      remediation: f.remediation,
      owasp_category: f.owasp_category as FindingInput["owasp_category"],
      mitre_technique: f.mitre_technique,
      confidence: f.confidence,
      evidence_chain:
        (f.evidence_chain as Record<string, unknown> | null) ?? null,
    }));

    if (findings.length > 0) {
      await this.db.insertFindings(server_id, scanId, findings);
    }

    const s = server.score;
    await this.db.insertScore({
      server_id,
      scan_id: scanId,
      total_score: s.total_score,
      code_score: s.code_score,
      deps_score: s.deps_score,
      config_score: s.config_score,
      description_score: s.description_score,
      behavior_score: s.behavior_score,
      owasp_coverage: s.owasp_coverage,
      rules_version: result.rules_version,
      total_score_v2: s.total_score_v2,
      techniques_v2:
        Object.keys(s.techniques_v2).length === 0 ? null : s.techniques_v2,
      schema_score: s.schema_score,
      ecosystem_score: s.ecosystem_score,
      protocol_score: s.protocol_score,
      adversarial_score: s.adversarial_score,
      compliance_score: s.compliance_score,
      supply_chain_score: s.supply_chain_score,
      infrastructure_score: s.infrastructure_score,
      coverage_band: server.coverage.confidence_band,
      analysis_coverage: {
        had_source_code: server.coverage.had_source_code,
        had_connection: server.coverage.had_connection,
        had_dependencies: server.coverage.had_dependencies,
        coverage_ratio: server.coverage.coverage_ratio,
        techniques_run: server.coverage.techniques_run,
        rules_executed: server.coverage.rules_executed,
        rules_skipped_no_data: server.coverage.rules_skipped_no_data,
      },
    });

    await this.db.completeScan(scanId, findings.length, null, {
      source_fetched: result.input_type === "source",
      connection_attempted: server.endpoint !== null,
      connection_succeeded: server.connection_success,
      dependencies_audited: server.coverage.had_dependencies,
    });

    return slug;
  }

  private async safeFail(jobId: string, message: string): Promise<void> {
    try {
      await this.db.failScanJob(jobId, message);
    } catch (err) {
      logger.error({ jobId, err }, "Failed to mark job failed");
    }
  }
}
