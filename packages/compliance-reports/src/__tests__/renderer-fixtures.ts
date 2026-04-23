import { buildReport } from "../build-report.js";
import { signReport } from "../attestation.js";
import type { FrameworkId, SignedComplianceReport } from "../types.js";

/**
 * Produce a deterministic signed report for renderer tests. The same input
 * parameters always yield byte-identical `report` bytes (buildReport is
 * deterministic given an explicit `assessed_at`). The signed envelope's
 * `signed_at` is overridden after sign-time so test-level byte-identical
 * comparisons are possible.
 */
export function makeSyntheticSignedReport(
  framework_id: FrameworkId,
  overrides: Partial<{ serverName: string; serverSlug: string }> = {},
): SignedComplianceReport {
  const report = buildReport({
    framework_id,
    server: {
      slug: overrides.serverSlug ?? "test-server",
      name: overrides.serverName ?? "Test Server",
      github_url: "https://github.com/test/server",
      scan_id: "scan-00000000-0000-0000-0000-000000000001",
    },
    findings: [
      {
        id: "f1",
        rule_id: "C1",
        severity: "critical",
        evidence: "exec(req.body.cmd) at src/handlers/run.ts:42",
        confidence: 0.95,
        remediation: "Use execFile() with a fixed argument vector.",
      },
      {
        id: "f2",
        rule_id: "I15",
        severity: "high",
        evidence: "session id uses Math.random() at src/session.ts:18",
        confidence: 0.85,
        remediation: "Use crypto.randomUUID() for session identifiers.",
      },
    ],
    coverage: { band: "high", ratio: 0.85, techniques_run: ["ast-taint", "structural"] },
    rules_version: "2026-04-23-164rules",
    sentinel_version: "0.4.0",
    kill_chains: [],
    assessed_at: "2026-04-23T12:00:00.000Z",
  });
  const signed = signReport(report, { key: "test-key", key_id: "test-key-id" });
  // Pin signed_at so byte-level comparisons across test invocations succeed.
  signed.attestation.signed_at = "2026-04-23T12:00:00.000Z";
  // Re-sign with the pinned timestamp included? signed_at is NOT covered by
  // the HMAC per attestation.ts, so overriding here is safe.
  return signed;
}
