/**
 * K17 TN-03 — `axios.defaults.timeout` set at module scope. Subsequent
 * axios calls are covered by the global. Expected: no finding.
 */

import axios from "axios";

axios.defaults.timeout = 8000;

export async function fetchUser(id: string): Promise<unknown> {
  const { data } = await axios.get(`https://api.example.com/users/${id}`);
  return data;
}
