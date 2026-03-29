/**
 * Test Fixture Edges — Reusable RiskEdge factories
 *
 * Each edge models what the risk-matrix patterns (P01-P12) would produce
 * when analyzing a server configuration.
 */
import type { RiskEdge, EdgeType } from "../../types.js";

export function makeEdge(
  from: string,
  to: string,
  type: EdgeType,
  severity: RiskEdge["severity"] = "critical",
  patternId?: string
): RiskEdge {
  return {
    from_server_id: `srv-${from}`,
    to_server_id: `srv-${to}`,
    edge_type: type,
    severity,
    description: `${from} → ${to} (${type})`,
    owasp: "MCP04",
    mitre: "AML.T0057",
    pattern_id: patternId,
  };
}

// ── KC01 edges (injection → data → exfil) ─────────────────────────────────────

export function kc01Edges(): RiskEdge[] {
  return [
    makeEdge("web-scraper", "file-manager", "injection_path", "critical", "P01"),
    makeEdge("file-manager", "webhook-sender", "exfiltration_chain", "critical", "P01"),
  ];
}

// ── KC02 edges (config poisoning → execution) ─────────────────────────────────

export function kc02Edges(): RiskEdge[] {
  return [
    makeEdge("config-writer", "code-runner", "config_poisoning", "critical", "P05"),
  ];
}

// ── KC03 edges (credential harvest → exfil) ───────────────────────────────────

export function kc03Edges(): RiskEdge[] {
  return [
    makeEdge("credential-store", "webhook-sender", "credential_chain", "critical", "P02"),
    makeEdge("credential-store", "webhook-sender", "exfiltration_chain", "critical", "P02"),
  ];
}

// ── KC04 edges (injection → memory → read) ────────────────────────────────────

export function kc04Edges(): RiskEdge[] {
  return [
    makeEdge("email-reader", "memory-writer", "injection_path", "critical", "P04"),
    makeEdge("memory-writer", "memory-reader", "memory_pollution", "high", "P04"),
  ];
}

// ── KC05 edges (injection → codegen → exec) ───────────────────────────────────

export function kc05Edges(): RiskEdge[] {
  return [
    makeEdge("web-scraper", "code-generator", "injection_path", "critical", "P07"),
    makeEdge("code-generator", "code-runner", "injection_path", "critical", "P07"),
  ];
}

// ── KC06 edges (data → pivot → exfil) ─────────────────────────────────────────

export function kc06Edges(): RiskEdge[] {
  return [
    makeEdge("credential-store", "code-runner", "data_flow", "high", "P12"),
    makeEdge("code-runner", "webhook-sender", "exfiltration_chain", "high", "P12"),
  ];
}

// ── KC07 edges (db recon → db admin → exfil) ──────────────────────────────────

export function kc07Edges(): RiskEdge[] {
  return [
    makeEdge("db-reader", "db-admin", "privilege_escalation", "critical", "P08"),
    makeEdge("db-admin", "webhook-sender", "exfiltration_chain", "high", "P08"),
  ];
}
