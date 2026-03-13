/**
 * TEST FIXTURE — Intentionally Vulnerable MCP Server
 * This file is used by test-scan.ts to validate detection rules fire correctly.
 * DO NOT deploy this code. Every vulnerability here is intentional.
 */

import { exec, execSync } from "child_process";
import { createServer } from "http";
import { readFileSync } from "fs";
import pg from "pg";
import express from "express";

// C5: Hardcoded credentials (rule C5 — hardcoded secrets)
const OPENAI_API_KEY = "sk-proj-abcdef1234567890abcdef1234567890abcdef1234567890";
const GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE";
const STRIPE_KEY = "sk_live_xxxxxxxxxxxxxxxxxxxxxxxx";

// C7: Wildcard CORS (rule C7)
const app = express();
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  next();
});

// C8: Listening on 0.0.0.0 with no auth (rule C8)
createServer(app).listen(3000, "0.0.0.0");

// C1: Command injection via exec with user input (rule C1)
export async function runCommand(userInput: string) {
  return new Promise((resolve, reject) => {
    exec(`ls ${userInput}`, (err, stdout) => {
      if (err) reject(err);
      else resolve(stdout);
    });
  });
}

// C1: execSync with user input (rule C1)
export function runSync(cmd: string) {
  return execSync(cmd).toString();
}

// C4: SQL injection via template literal (rule C4)
const client = new pg.Client();
export async function queryUser(userId: string) {
  return client.query(`SELECT * FROM users WHERE id = '${userId}'`);
}

// C9: Excessive filesystem scope — reads from root (rule C9)
export function readSystemFile(path: string) {
  return readFileSync(`/${path}`).toString();
}

// C2: Path traversal (rule C2)
export function getFile(name: string) {
  return readFileSync(`./uploads/../../../${name}`).toString();
}

// C16: Dynamic code evaluation with user input (rule C16)
export function evaluateExpression(expr: string) {
  return eval(expr);
}

// C10: Prototype pollution (rule C10)
export function mergeConfig(base: object, user: Record<string, unknown>) {
  return Object.assign({}, base, (user as any).__proto__);
}

// C14: JWT with 'none' algorithm acceptance (rule C14)
import jwt from "jsonwebtoken";
export function verifyToken(token: string) {
  return jwt.verify(token, "", { algorithms: ["none", "HS256"] });
}

// C15: Timing attack on secret comparison (rule C15)
export function checkApiKey(provided: string, stored: string) {
  return provided === stored; // should use crypto.timingSafeEqual
}
