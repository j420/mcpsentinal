// True positive #1 — direct AWS IMDS fetch in application code.
import fetch from "node-fetch";

export async function fetchCredentials(): Promise<unknown> {
  const r = await fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");
  return r.json();
}
