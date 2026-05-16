"use client";

/**
 * ScanResultView — polls an ad-hoc scan job and renders the report.
 *
 * The job runs asynchronously in the API. While it is queued/running this
 * component polls GET /api/v1/scan/:id every 2s; once terminal it renders
 * the per-server security report (or the failure reason).
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3100";
const POLL_INTERVAL_MS = 2000;

type Severity = "critical" | "high" | "medium" | "low" | "informational";
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

interface Finding {
  rule_id: string;
  severity: Severity;
  evidence: string;
  remediation: string;
  owasp_category: string | null;
  mitre_technique: string | null;
  confidence: number;
}

interface ScannedServer {
  name: string;
  endpoint: string | null;
  connection_success: boolean;
  connection_error: string | null;
  tool_count: number;
  findings: Finding[];
  score: { total_score: number };
  coverage: { confidence_band: string; coverage_ratio: number; rules_executed: number };
  registered_slug: string | null;
}

interface ScanResult {
  input_type: string;
  rules_version: string;
  servers: ScannedServer[];
  unscannable_stdio: Array<{ name: string; reason: string }>;
  warnings: string[];
}

interface ScanJob {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  input_type: string;
  coverage_band: string | null;
  result: ScanResult | null;
  error: string | null;
  registered_server_slugs: string[];
}

function scoreLabel(score: number): { label: string; cls: string } {
  if (score >= 80) return { label: "Good", cls: "good" };
  if (score >= 60) return { label: "Moderate", cls: "moderate" };
  if (score >= 40) return { label: "Poor", cls: "poor" };
  return { label: "Critical", cls: "critical" };
}

export default function ScanResultView({ id }: { id: string }) {
  const router = useRouter();
  const [job, setJob] = useState<ScanJob | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [networkError, setNetworkError] = useState(false);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function poll() {
      try {
        const res = await fetch(`${API_URL}/api/v1/scan/${id}`);
        if (!active) return;
        if (res.status === 404) {
          setNotFound(true);
          return;
        }
        if (!res.ok) {
          setNetworkError(true);
          return;
        }
        const data: ScanJob = await res.json();
        if (!active) return;
        setJob(data);
        if (data.status === "queued" || data.status === "running") {
          timer = setTimeout(poll, POLL_INTERVAL_MS);
        }
      } catch {
        if (active) setNetworkError(true);
      }
    }

    poll();
    return () => {
      active = false;
      if (timer) clearTimeout(timer);
    };
  }, [id]);

  // A successful single-server scan lands directly on the registered
  // server's detail page — that page renders the FULL report (categories,
  // sub-categories, rules, tests, passed/skipped, evidence chains). The
  // /scan/:id page is only the queued/running/failed surface plus the
  // multi-server config summary.
  useEffect(() => {
    if (
      job?.status === "succeeded" &&
      job.registered_server_slugs.length === 1
    ) {
      router.replace(`/servers/${job.registered_server_slugs[0]}`);
    }
  }, [job, router]);

  if (notFound) {
    return (
      <div className="scan-state scan-state-error">
        <h1 className="scan-state-title">Scan not found</h1>
        <p>This scan does not exist or has expired. Scans are kept for 7 days.</p>
        <a className="btn-primary" href="/scan">Start a new scan</a>
      </div>
    );
  }

  if (networkError) {
    return (
      <div className="scan-state scan-state-error">
        <h1 className="scan-state-title">Could not load the scan</h1>
        <p>The scanner could not be reached. Please retry shortly.</p>
      </div>
    );
  }

  if (!job || job.status === "queued" || job.status === "running") {
    return (
      <div className="scan-state">
        <div className="scan-spinner" aria-hidden="true" />
        <h1 className="scan-state-title">
          {job?.status === "running" ? "Scanning…" : "Queued…"}
        </h1>
        <p>
          Connecting to the server, enumerating tools, and running the
          detection rules. This usually takes under a minute.
        </p>
      </div>
    );
  }

  if (job.status === "failed") {
    return (
      <div className="scan-state scan-state-error">
        <h1 className="scan-state-title">Scan failed</h1>
        <p>{job.error ?? "The scan could not be completed."}</p>
        <a className="btn-primary" href="/scan">Try another scan</a>
      </div>
    );
  }

  const result = job.result;
  if (!result || result.servers.length === 0) {
    return (
      <div className="scan-state scan-state-error">
        <h1 className="scan-state-title">Nothing to report</h1>
        <p>The scan completed but produced no analysable server.</p>
        <a className="btn-primary" href="/scan">Start a new scan</a>
      </div>
    );
  }

  // Single-server scan → the redirect effect is taking us to the full
  // report. Show a brief hand-off rather than flashing the summary.
  if (job.registered_server_slugs.length === 1) {
    return (
      <div className="scan-state">
        <div className="scan-spinner" aria-hidden="true" />
        <h1 className="scan-state-title">Scan complete</h1>
        <p>Opening the full report…</p>
        <a
          className="btn-primary"
          href={`/servers/${job.registered_server_slugs[0]}`}
        >
          View the full report →
        </a>
      </div>
    );
  }

  return (
    <div className="scan-report">
      <div className="scan-report-head">
        <div className="hero-eyebrow">
          <span className="hero-eyebrow-mark" aria-hidden="true">SCAN COMPLETE</span>
          <span aria-hidden="true">·</span>
          <span>{result.input_type} scan · rules v{result.rules_version}</span>
        </div>
        <h1 className="scan-report-title">
          {result.servers.length === 1
            ? result.servers[0].name
            : `${result.servers.length} servers scanned`}
        </h1>
      </div>

      {result.warnings.length > 0 && (
        <div className="scan-banner scan-banner-warn">
          <strong>Notes</strong>
          <ul>
            {result.warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      {result.unscannable_stdio.length > 0 && (
        <div className="scan-banner scan-banner-info">
          <strong>Local stdio servers were skipped</strong>
          <ul>
            {result.unscannable_stdio.map((s, i) => (
              <li key={i}>
                <code>{s.name}</code> — {s.reason}
              </li>
            ))}
          </ul>
        </div>
      )}

      {result.servers.map((server, idx) => (
        <ServerReport key={idx} server={server} />
      ))}
    </div>
  );
}

function ServerReport({ server }: { server: ScannedServer }) {
  const { label, cls } = scoreLabel(server.score.total_score);
  const findingsBySeverity = SEVERITIES.map((sev) => ({
    sev,
    items: server.findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <section className="scan-server">
      <div className="scan-score-hero">
        <div className={`scan-score-num scan-score-${cls}`}>
          {server.score.total_score}
          <span className="scan-score-denom">/100</span>
        </div>
        <div className="scan-score-meta">
          <span className={`scan-score-label scan-score-${cls}`}>{label}</span>
          <span className="scan-server-name">{server.name}</span>
          <span className="scan-score-sub">
            {server.findings.length} finding{server.findings.length === 1 ? "" : "s"}
            {" · "}
            {server.tool_count} tool{server.tool_count === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      <div className="scan-banner scan-banner-info">
        Coverage: <strong>{server.coverage.confidence_band}</strong> confidence
        {" — "}
        {server.coverage.rules_executed} rules applied to the available data.
        {server.coverage.confidence_band === "minimal" ||
        server.coverage.confidence_band === "low"
          ? " A URL-only scan cannot run code, dependency or supply-chain rules — scan the GitHub/npm source for the full 164-rule suite."
          : ""}
      </div>

      {server.registered_slug && (
        <p className="scan-registered">
          <a
            className="btn-primary"
            href={`/servers/${server.registered_slug}`}
          >
            View the full report →
          </a>
          <span className="scan-registered-note">
            Categories, sub-categories, every rule, its tests and the full
            evidence chains — plus passed and skipped rules.
          </span>
        </p>
      )}

      {findingsBySeverity.length === 0 ? (
        <p className="scan-clean">No findings across the applied rules.</p>
      ) : (
        findingsBySeverity.map((group) => (
          <div key={group.sev} className="scan-finding-group">
            <h3 className="scan-finding-group-title">
              <span className={`sev-badge sev-${group.sev}`}>{group.sev}</span>
              <span>{group.items.length}</span>
            </h3>
            {group.items.map((f, i) => (
              <div key={i} className="scan-finding">
                <div className="scan-finding-head">
                  <span className="scan-finding-rule">{f.rule_id}</span>
                  {f.owasp_category && (
                    <span className="scan-finding-tag">{f.owasp_category}</span>
                  )}
                  {f.mitre_technique && (
                    <span className="scan-finding-tag">{f.mitre_technique}</span>
                  )}
                  <span className="scan-finding-conf">
                    {Math.round(f.confidence * 100)}% confidence
                  </span>
                </div>
                <p className="scan-finding-evidence">{f.evidence}</p>
                <p className="scan-finding-fix">
                  <strong>Fix:</strong> {f.remediation}
                </p>
              </div>
            ))}
          </div>
        ))
      )}
    </section>
  );
}
