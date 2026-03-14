/**
 * P9 — Scanner Engine Engineer
 * DependencyAuditor — enriches raw dependencies with CVE data from the OSV database.
 *
 * Uses the Open Source Vulnerabilities (OSV) API (https://osv.dev):
 * - Free, no authentication required
 * - Covers npm, PyPI, Cargo, Go, and more
 * - Returns structured vulnerability data with CVE aliases
 * - Rate limit: generous, but we batch and delay to be a good API citizen
 *
 * Design principles:
 * - Batch queries to reduce API round-trips
 * - Settled Promise.allSettled — one failed dep query never aborts the batch
 * - Brief inter-batch delay to avoid hammering the API
 * - Returns full EnrichedDependency array even if audit partially fails
 * - All errors are logged + swallowed — audit failure is non-fatal to scan
 */

import pino from "pino";
import type { RawDependency, EnrichedDependency } from "./types.js";

const logger = pino({ name: "scanner:auditor" });

const OSV_BASE = process.env.OSV_API_URL ?? "https://api.osv.dev/v1";
const OSV_BATCH_API = `${OSV_BASE}/querybatch`;
const OSV_QUERY_API = `${OSV_BASE}/query`;
const MAX_BATCH_SIZE = 20;
const INTER_BATCH_DELAY_MS = 150;
const REQUEST_TIMEOUT_MS = 12_000;

// OSV ecosystem names differ from our internal names
const ECOSYSTEM_MAP: Record<RawDependency["ecosystem"], string> = {
  npm: "npm",
  pypi: "PyPI",
};

interface OsvVuln {
  id: string;
  aliases?: string[];
}

interface OsvQueryResult {
  vulns?: OsvVuln[];
}

interface OsvBatchResponse {
  results: OsvQueryResult[];
}

export class DependencyAuditor {
  /**
   * Enrich an array of raw dependencies with CVE data from the OSV database.
   *
   * Uses the OSV batch API when possible (up to 20 packages per request),
   * falling back to individual queries for packages where batch fails.
   *
   * @param rawDeps - Dependencies parsed from package.json or pyproject.toml
   * @returns Enriched dependencies with has_known_cve and cve_ids populated
   */
  async audit(rawDeps: RawDependency[]): Promise<EnrichedDependency[]> {
    if (rawDeps.length === 0) return [];

    const results: EnrichedDependency[] = [];

    // Process in batches of MAX_BATCH_SIZE
    for (let i = 0; i < rawDeps.length; i += MAX_BATCH_SIZE) {
      const batch = rawDeps.slice(i, i + MAX_BATCH_SIZE);

      try {
        const batchResults = await this.queryBatch(batch);
        results.push(...batchResults);
      } catch (batchErr) {
        // Batch API failed — fall back to individual queries for this batch
        logger.warn({ err: batchErr }, "OSV batch query failed — falling back to individual queries");
        const individualResults = await this.queryIndividual(batch);
        results.push(...individualResults);
      }

      // Be polite to the API — brief pause between batches (not after the last one)
      if (i + MAX_BATCH_SIZE < rawDeps.length) {
        await delay(INTER_BATCH_DELAY_MS);
      }
    }

    const withCves = results.filter((d) => d.has_known_cve).length;
    logger.info(
      { total: results.length, with_cves: withCves },
      "Dependency audit complete"
    );

    return results;
  }

  // ─── Private: Batch Query ─────────────────────────────────────────────────

  /**
   * Query OSV batch API — up to 20 packages per request.
   * OSV batch API: POST /v1/querybatch with { queries: [...] }
   */
  private async queryBatch(deps: RawDependency[]): Promise<EnrichedDependency[]> {
    const queries = deps.map((dep) => ({
      package: {
        name: dep.name,
        ecosystem: ECOSYSTEM_MAP[dep.ecosystem],
      },
      ...(dep.version ? { version: dep.version } : {}),
    }));

    const resp = await fetch(OSV_BATCH_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!resp.ok) {
      throw new Error(`OSV batch API returned HTTP ${resp.status}`);
    }

    const data = (await resp.json()) as OsvBatchResponse;

    if (!Array.isArray(data.results) || data.results.length !== deps.length) {
      throw new Error(
        `OSV batch response length mismatch: expected ${deps.length}, got ${data.results?.length ?? 0}`
      );
    }

    return deps.map((dep, idx) => this.buildEnriched(dep, data.results[idx]));
  }

  // ─── Private: Individual Fallback Query ──────────────────────────────────

  /**
   * Query each dependency individually as a fallback when the batch API fails.
   * Uses Promise.allSettled — a single failure never blocks the rest.
   */
  private async queryIndividual(deps: RawDependency[]): Promise<EnrichedDependency[]> {
    const settled = await Promise.allSettled(
      deps.map(async (dep): Promise<EnrichedDependency> => {
        try {
          const body = {
            package: {
              name: dep.name,
              ecosystem: ECOSYSTEM_MAP[dep.ecosystem],
            },
            ...(dep.version ? { version: dep.version } : {}),
          };

          const resp = await fetch(OSV_QUERY_API, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          });

          if (!resp.ok) {
            logger.warn({ dep: dep.name, status: resp.status }, "OSV individual query failed");
            return this.noVuln(dep);
          }

          const result = (await resp.json()) as OsvQueryResult;
          return this.buildEnriched(dep, result);
        } catch (err) {
          logger.warn({ dep: dep.name, err }, "OSV individual query threw");
          return this.noVuln(dep);
        }
      })
    );

    return settled.map((r, idx) =>
      r.status === "fulfilled" ? r.value : this.noVuln(deps[idx])
    );
  }

  // ─── Private: Result Builders ─────────────────────────────────────────────

  /**
   * Build an EnrichedDependency from a raw dep + OSV query result.
   * Extracts CVE IDs from the aliases array (OSV uses its own IDs; CVE IDs are aliases).
   */
  private buildEnriched(dep: RawDependency, result: OsvQueryResult): EnrichedDependency {
    const vulns = result.vulns ?? [];

    // Collect CVE IDs from vuln aliases; deduplicate
    const cveIds = [
      ...new Set(
        vulns
          .flatMap((v) => [v.id, ...(v.aliases ?? [])])
          .filter((id) => id.startsWith("CVE-"))
      ),
    ];

    return {
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      has_known_cve: vulns.length > 0,
      cve_ids: cveIds,
      last_updated: null, // OSV doesn't return package last-updated date
    };
  }

  /** Return an enriched dep with no CVE data (used on error) */
  private noVuln(dep: RawDependency): EnrichedDependency {
    return {
      name: dep.name,
      version: dep.version,
      ecosystem: dep.ecosystem,
      has_known_cve: false,
      cve_ids: [],
      last_updated: null,
    };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
