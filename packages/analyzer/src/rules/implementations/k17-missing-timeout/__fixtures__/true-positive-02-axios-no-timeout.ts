/**
 * K17 TP-02 — axios.get without timeout; no global axios.defaults.timeout
 * in this file. Expected: one finding on the axios.get call.
 */

import axios from "axios";

export async function getUsers(): Promise<unknown> {
  const { data } = await axios.get("https://api.example.com/users");
  return data;
}
