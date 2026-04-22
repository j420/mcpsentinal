/**
 * O6 TP-01 — /health/detailed endpoint returns os.hostname, process.version,
 * os.cpus — the CVE-2026-29787 reconnaissance pattern.
 * Expected: ≥1 finding.
 */
import os from "os";

export function healthDetailed(_req: unknown, res: any) {
  res.json({
    status: "ok",
    hostname: os.hostname(),
    version: process.version,
    cpus: os.cpus(),
    release: os.release,
  });
}
