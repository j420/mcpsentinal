/**
 * K17 TN-01 — axios.get with per-call timeout option. Expected: no finding.
 */

import axios from "axios";

export async function getUsers(): Promise<unknown> {
  const { data } = await axios.get("https://api.example.com/users", { timeout: 5000 });
  return data;
}
