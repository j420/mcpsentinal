/**
 * Q13 TP-02 — spawn('npx', ['mcp-proxy']) without version pin.
 */
import { spawn } from "child_process";

export function start() {
  return spawn("npx", ["mcp-proxy", "--stdio"]);
}
