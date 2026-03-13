/**
 * TEST FIXTURE — Intentionally Vulnerable MCP Server
 * This file is used by test-scan.ts to validate detection rules fire correctly.
 * DO NOT deploy this code. Every vulnerability here is intentional.
 *
 * Uses only Node.js built-ins so the scanner package needs no extra devDeps.
 * The vulnerable *patterns* are what matter — the analyzer uses regex against
 * source text, not runtime behaviour.
 */

import { exec, execSync } from "child_process";
import { createServer, IncomingMessage, ServerResponse } from "http";
import { readFileSync } from "fs";
import { createHmac, timingSafeEqual } from "crypto";
import pg from "pg";

// ── C5: Hardcoded secrets (20+ formats covered by rule C5) ───────────────────
const OPENAI_API_KEY = "sk-proj-abcdef1234567890abcdef1234567890abcdef1234567890";
const GITHUB_TOKEN   = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const AWS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY     = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx";
const ANTHROPIC_KEY  = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// ── C7: Wildcard CORS — raw http (same pattern the rule detects) ─────────────
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "*");
  res.end("ok");
});

// ── C8: Listening on 0.0.0.0 with no auth ───────────────────────────────────
server.listen(3000, "0.0.0.0");

// ── C1: Command injection via exec with user input ───────────────────────────
export async function runCommand(userInput: string) {
  return new Promise((resolve, reject) => {
    exec(`ls ${userInput}`, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// ── C1: execSync with user input ─────────────────────────────────────────────
export function runSync(cmd: string) {
  return execSync(cmd).toString();
}

// ── C4: SQL injection via template literal ───────────────────────────────────
const client = new pg.Client();
export async function queryUser(userId: string) {
  return client.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

// ── C9: Excessive filesystem scope — reads from / ────────────────────────────
export function readSystemFile(path: string) {
  return readFileSync(`/${path}`).toString();
}

// ── C2: Path traversal ───────────────────────────────────────────────────────
export function getFile(name: string) {
  return readFileSync(`./uploads/../../../${name}`).toString();
}

// ── C16: Dynamic code evaluation with user input ─────────────────────────────
export function evaluateExpression(expr: string) {
  // eslint-disable-next-line no-eval
  return eval(expr);
}

// ── C10: Prototype pollution ─────────────────────────────────────────────────
export function mergeConfig(base: object, user: Record<string, unknown>) {
  return Object.assign({}, base, (user as Record<string, unknown>)["__proto__"]);
}

// ── C14: JWT algorithm confusion — inline pattern (no jsonwebtoken import) ───
// Vulnerable: accepts 'none' algorithm, skips signature verification.
// Rule C14 detects: algorithms: ["none" in source text.
export function verifyToken(token: string): Record<string, unknown> {
  const [headerB64, payloadB64] = token.split(".");
  const header = JSON.parse(Buffer.from(headerB64 ?? "", "base64url").toString());
  // VULNERABILITY: allowlist includes 'none' — attacker can forge tokens
  const allowedAlgorithms = ["none", "HS256"];
  if (!allowedAlgorithms.includes(header.alg)) {
    throw new Error("Algorithm not allowed");
  }
  // ignoreExpiration: true — another C14 pattern
  const ignoreExpiration = true;
  void ignoreExpiration; // suppress unused warning
  return JSON.parse(Buffer.from(payloadB64 ?? "", "base64url").toString());
}

// ── C15: Timing attack on secret comparison (=== instead of timingSafeEqual) ─
export function checkApiKey(provided: string, stored: string): boolean {
  // VULNERABILITY: timing-unsafe comparison leaks secret length via timing
  return provided === stored;
}

// ── Safe reference (to confirm timingSafeEqual is available if needed) ───────
export function safeCompare(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

void createHmac; // imported for safe reference above
