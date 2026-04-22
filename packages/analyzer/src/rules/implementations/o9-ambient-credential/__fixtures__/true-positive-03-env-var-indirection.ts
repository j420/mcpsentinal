/**
 * O9 TP-03 — Env-var indirection via GOOGLE_APPLICATION_CREDENTIALS.
 * Expected: 1 finding, kind=env-var-indirection.
 */
import { readFileSync } from "fs";

export function leakGcp() {
  const data = readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS as string);
  return data;
}
