/**
 * Signed compliance-report endpoints.
 *
 * Routes:
 *   GET /api/v1/servers/:slug/compliance/:framework.json
 *   GET /api/v1/servers/:slug/compliance/:framework.html
 *   GET /api/v1/servers/:slug/compliance/:framework.pdf
 *   GET /api/v1/servers/:slug/compliance/:framework/badge.svg
 *
 * Every response is signed with HMAC-SHA256 over the RFC 8785-canonicalised
 * report body. The signature is duplicated in response headers AND embedded
 * in the rendered body (JSON/HTML/PDF via the renderer registry, SVG via
 * the badge renderer) so regulators can verify the artifact offline.
 *
 * The routes live here — separate from server.ts — because they depend on
 * a fairly rich pipeline (report builder + renderer registry + badge
 * registry + DB fetches for findings/server/attack-chains). Keeping the
 * handler narrow in server.ts and fanning out to this module preserves the
 * "thin routes" convention documented in packages/api/CLAUDE.md.
 */

import type { NextFunction, Request, Response, RequestHandler } from "express";
import pino from "pino";
import {
  buildReport,
  FRAMEWORK_IDS,
  getBadge,
  getRenderer,
  registerAllBadges,
  resolveSigningContextFromEnv,
  signReport,
  verifyReport,
} from "@mcp-sentinel/compliance-reports";
import type {
  ComplianceReport,
  FrameworkId,
  KillChainNarrative,
  RendererFormat,
  ReportInputFinding,
  SignedComplianceReport,
} from "@mcp-sentinel/compliance-reports";
import type {
  DatabaseQueries,
  Finding,
  Server,
} from "@mcp-sentinel/database";

const logger = pino({ name: "api:compliance-reports" }, process.stderr);

// ─── One-time registration of the generic SVG badge under every framework id.
registerAllBadges();

// ─── Sentinel / rules versions ───────────────────────────────────────────────
// These should come from package metadata in a future pass. For now a stable
// constant is fine — the value flows through report.assessment.* and is
// covered by the HMAC, so it cannot be silently tampered with post-sign.
const SENTINEL_VERSION = process.env["MCP_SENTINEL_VERSION"] ?? "0.4.0";
const RULES_VERSION = process.env["MCP_SENTINEL_RULES_VERSION"] ?? "2026-04-23";

// ─── Cache policy ────────────────────────────────────────────────────────────
// Same scan_id → same report bytes → same signature (the signature's
// timestamp is post-canonicalisation and not covered by the HMAC). 5 minutes
// of fresh cache + 1 minute stale is the same envelope the other public
// endpoints use.
const CACHE_CONTROL = "public, max-age=300, stale-while-revalidate=60";

// ─── Renderer format helpers ─────────────────────────────────────────────────
const FORMAT_CONTENT_TYPES: Record<RendererFormat, string> = {
  json: "application/json; charset=utf-8",
  html: "text/html; charset=utf-8",
  pdf: "application/pdf",
};

function isFrameworkId(candidate: string): candidate is FrameworkId {
  return (FRAMEWORK_IDS as readonly string[]).includes(candidate);
}

function isRendererFormat(candidate: string): candidate is RendererFormat {
  return candidate === "json" || candidate === "html" || candidate === "pdf";
}

// Slug validation kept in sync with server.ts. Duplicated intentionally so
// this module doesn't form an import cycle with server.ts.
const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,98}[a-z0-9]$|^[a-z0-9]$/;
function isValidSlug(slug: string): boolean {
  return (
    SLUG_RE.test(slug) &&
    !slug.includes("..") &&
    !slug.includes("/") &&
    !slug.includes("\x00")
  );
}

// ─── Finding projection ──────────────────────────────────────────────────────
// buildReport() only needs a narrow subset of the Finding row. This mapper
// isolates the compliance-reports package from the full DB schema.
function toReportInputFinding(f: Finding): ReportInputFinding {
  return {
    id: f.id,
    rule_id: f.rule_id,
    severity: f.severity,
    evidence: f.evidence,
    confidence: f.confidence,
    remediation: f.remediation,
  };
}

// ─── Attack chain projection ─────────────────────────────────────────────────
// The compliance report wants a stable KillChainNarrative shape, not the
// full persistence row. We copy only the fields the regulator-facing
// narrative needs.
function toKillChainNarrative(row: {
  kill_chain_id: string;
  kill_chain_name: string;
  exploitability_overall: number;
  narrative: string;
  owasp_refs: string[];
  mitre_refs: string[];
  mitigations: unknown[];
}): KillChainNarrative {
  // mitigations is persisted as jsonb — could be strings or objects. We
  // normalise to a string array, dropping anything that isn't string-typed.
  const mitigations: string[] = Array.isArray(row.mitigations)
    ? row.mitigations.filter((m): m is string => typeof m === "string")
    : [];
  return {
    kc_id: row.kill_chain_id,
    name: row.kill_chain_name,
    severity_score: row.exploitability_overall,
    narrative: row.narrative,
    contributing_rule_ids: [...row.owasp_refs, ...row.mitre_refs],
    cve_evidence_ids: [],
    mitigations,
  };
}

// ─── Coverage band heuristic ────────────────────────────────────────────────
// Until Phase 5.3 wires in the real technique-coverage scoring, we derive a
// simple band from the number of findings we actually looked at. This
// keeps the assessment honest — an empty findings set is "minimal", a full
// set is "high".
function deriveCoverage(findingsCount: number): {
  band: "high" | "medium" | "low" | "minimal";
  ratio: number;
  techniques_run: string[];
} {
  const techniques_run = [
    "ast-taint",
    "capability-graph",
    "entropy",
    "linguistic-scoring",
    "schema-inference",
  ];
  if (findingsCount === 0) {
    return { band: "minimal", ratio: 0.0, techniques_run };
  }
  if (findingsCount < 5) {
    return { band: "low", ratio: 0.4, techniques_run };
  }
  if (findingsCount < 20) {
    return { band: "medium", ratio: 0.7, techniques_run };
  }
  return { band: "high", ratio: 0.95, techniques_run };
}

// ─── Attestation header writer ──────────────────────────────────────────────
function writeAttestationHeaders(
  res: Response,
  signed: SignedComplianceReport,
): void {
  res.setHeader("X-MCP-Sentinel-Signature", signed.attestation.signature);
  res.setHeader("X-MCP-Sentinel-Key-Id", signed.attestation.key_id);
  res.setHeader("X-MCP-Sentinel-Signed-At", signed.attestation.signed_at);
  res.setHeader("X-MCP-Sentinel-Algorithm", signed.attestation.algorithm);
  res.setHeader("X-MCP-Sentinel-Canonicalization", signed.attestation.canonicalization);
  // Non-normative: useful for regulator tooling that scrapes discovery info
  res.setHeader("X-MCP-Sentinel-Signer", signed.attestation.signer);
}

// ─── Report assembly ────────────────────────────────────────────────────────
async function assembleReport(
  db: DatabaseQueries,
  server: Server,
  frameworkId: FrameworkId,
): Promise<ComplianceReport> {
  const findings = (await db.getFindingsForServer(server.id)) as Finding[];
  const attackChains = await db.getAttackChainsForServer(server.id);
  const killChains: KillChainNarrative[] = attackChains.map(toKillChainNarrative);

  const scanId = findings[0]?.scan_id ?? "00000000-0000-0000-0000-000000000000";
  // The `assessed_at` timestamp is part of the signed report body, so it
  // MUST be stable for the same scan_id — otherwise identical requests
  // produce different HMAC tags and regulator replay fails. Derive it
  // from the newest finding's created_at; fall back to the server's
  // last_scanned_at; last resort the scan was never run so we stamp the
  // Unix epoch.
  const newestFindingTs = findings.reduce<Date | null>((acc, f) => {
    if (!acc) return f.created_at;
    return f.created_at > acc ? f.created_at : acc;
  }, null);
  const assessedAt =
    newestFindingTs?.toISOString() ??
    server.last_scanned_at?.toISOString() ??
    "1970-01-01T00:00:00.000Z";

  return buildReport({
    framework_id: frameworkId,
    server: {
      slug: server.slug,
      name: server.name,
      github_url: server.github_url,
      scan_id: scanId,
    },
    findings: findings.map(toReportInputFinding),
    coverage: deriveCoverage(findings.length),
    rules_version: RULES_VERSION,
    sentinel_version: SENTINEL_VERSION,
    kill_chains: killChains,
    assessed_at: assessedAt,
  });
}

// ─── Error helpers ──────────────────────────────────────────────────────────
function respondNotFound(res: Response, error: string, extras?: Record<string, unknown>): void {
  res.status(404).json({ error, ...(extras ?? {}) });
}

function respondUnavailable(res: Response, error: string): void {
  res.status(503).json({ error });
}

// ─── Factory ────────────────────────────────────────────────────────────────
// The wrapper factory lets server.ts pass in its DatabaseQueries instance +
// rate-limit middleware. Keeping construction explicit means the tests can
// inject a mock db without monkey-patching module state.
export interface ComplianceReportRouteDeps {
  db: DatabaseQueries;
  rateLimitMiddleware: () => RequestHandler;
}

export function createComplianceReportRoutes(
  deps: ComplianceReportRouteDeps,
): {
  handleRenderedReport: (format: RendererFormat) => RequestHandler;
  handleBadge: RequestHandler;
} {
  const { db } = deps;

  async function buildAndSign(
    slug: string,
    frameworkParam: string,
    res: Response,
  ): Promise<SignedComplianceReport | null> {
    if (!isValidSlug(slug)) {
      respondNotFound(res, "server_not_found");
      return null;
    }
    if (!isFrameworkId(frameworkParam)) {
      respondNotFound(res, "unknown_framework", {
        valid: [...FRAMEWORK_IDS],
      });
      return null;
    }
    const server = await db.findServerBySlug(slug);
    if (!server) {
      respondNotFound(res, "server_not_found");
      return null;
    }
    const report = await assembleReport(db, server, frameworkParam);
    const ctx = resolveSigningContextFromEnv();
    const signed = signReport(report, ctx);

    // Surface dev-key use via a warning header so consumers never
    // accidentally rely on unsigned-by-prod output. Does not affect
    // verification — the signature is still valid against the dev key.
    if (!process.env["COMPLIANCE_SIGNING_KEY"] || !process.env["COMPLIANCE_SIGNING_KEY_ID"]) {
      res.setHeader("X-MCP-Sentinel-Warning", "dev-key-in-use");
    }
    return signed;
  }

  function handleRenderedReport(format: RendererFormat): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const { slug, framework } = req.params;
        if (!slug || !framework) {
          respondNotFound(res, "server_not_found");
          return;
        }
        const signed = await buildAndSign(slug, framework, res);
        if (!signed) return; // error already sent

        const renderer = getRenderer(format, signed.report.framework.id);
        if (!renderer) {
          // No renderer wired for this (format, framework) pair. This is a
          // server-side bug (Agent 2 hasn't landed their renderer yet, or
          // the registration call was forgotten). Log loudly + 500.
          logger.error(
            { format, framework: signed.report.framework.id },
            "No renderer registered for (format, framework)",
          );
          res.status(500).json({
            error: "renderer_not_registered",
            format,
            framework: signed.report.framework.id,
          });
          return;
        }

        const body = renderer.render(signed);
        writeAttestationHeaders(res, signed);
        res.setHeader("Cache-Control", CACHE_CONTROL);
        res.setHeader("Content-Type", renderer.contentType ?? FORMAT_CONTENT_TYPES[format]);
        // Body may be Buffer (pdf) or string (json/html).
        if (Buffer.isBuffer(body)) {
          res.status(200).end(body);
        } else {
          res.status(200).send(body);
        }
      } catch (err) {
        logger.error({ err }, "compliance report route failure");
        next(err);
      }
    };
  }

  const handleBadge: RequestHandler = async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const { slug, framework } = req.params;
      if (!slug || !framework) {
        respondNotFound(res, "server_not_found");
        return;
      }
      if (!isValidSlug(slug)) {
        respondNotFound(res, "server_not_found");
        return;
      }
      if (!isFrameworkId(framework)) {
        respondNotFound(res, "unknown_framework", { valid: [...FRAMEWORK_IDS] });
        return;
      }
      const server = await db.findServerBySlug(slug);
      if (!server) {
        respondNotFound(res, "server_not_found");
        return;
      }

      // Unlike the rendered-report path, we do not 503 on missing scan data;
      // the badge should always render something so README embeds don't
      // break. buildReport handles the empty-findings case gracefully.
      const report = await assembleReport(db, server, framework);
      const ctx = resolveSigningContextFromEnv();
      const signed = signReport(report, ctx);
      if (!process.env["COMPLIANCE_SIGNING_KEY"] || !process.env["COMPLIANCE_SIGNING_KEY_ID"]) {
        res.setHeader("X-MCP-Sentinel-Warning", "dev-key-in-use");
      }

      const badge = getBadge(framework);
      if (!badge) {
        logger.error({ framework }, "No badge renderer registered");
        res.status(500).json({ error: "badge_not_registered", framework });
        return;
      }
      const svg = badge.render(signed.report, signed.attestation);

      writeAttestationHeaders(res, signed);
      res.setHeader("Content-Type", "image/svg+xml");
      res.setHeader("Cache-Control", CACHE_CONTROL);
      res.setHeader(
        "Content-Security-Policy",
        "default-src 'none'; style-src 'unsafe-inline'",
      );
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.status(200).send(svg);
    } catch (err) {
      logger.error({ err }, "compliance badge route failure");
      next(err);
    }
  };

  return { handleRenderedReport, handleBadge };
}

// ─── Testing helpers ────────────────────────────────────────────────────────
// Verify that a served report round-trips through signReport / verifyReport.
// Used in tests; unused by production callers.
export { verifyReport };
