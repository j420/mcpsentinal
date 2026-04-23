import type { Framework } from "./types.js";

/**
 * CoSAI (Coalition for Secure AI) MCP Security Threat Taxonomy T1–T12.
 * Mapping sourced from `agent_docs/detection-rules.md` and per-rule K-series
 * documentation ("CoSAI MCP-Tx" references).
 */
export const COSAI_MCP: Framework = {
  id: "cosai_mcp",
  name: "CoSAI MCP Security Threat Taxonomy",
  version: "2026-01",
  last_updated: "2026-04-23",
  source_url: "https://coalitionforsecureai.org/mcp-security/",
  controls: [
    {
      control_id: "CoSAI-T1",
      control_name: "Identity & Authentication Abuse",
      control_description:
        "Attacks against MCP authentication: absent auth, token lifecycle issues, OAuth misconfigurations, TOFU bypass.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["E1", "H1", "K6", "K7", "K8", "I15", "N14"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T2",
      control_name: "Authorization & Consent Bypass",
      control_description:
        "Attacks that sidestep user consent — auto-approve patterns, annotation deception that tricks consent-light AI clients.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["K4", "K5", "I1", "I2", "I16"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T3",
      control_name: "Code-Level Vulnerabilities",
      control_description:
        "Exploitable server code — command injection, path traversal, SSRF, SQL injection, XSS in tool responses.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: [
        "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9",
        "C10", "C11", "C12", "C13", "C14", "C15", "C16",
        "J2", "J7",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T4",
      control_name: "Prompt & Tool Content Manipulation",
      control_description:
        "Attacker-controlled content reaches the agent via tool descriptions, schema fields, init metadata, or tool responses.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: [
        "A1", "A5", "A7", "A8", "A9",
        "B5",
        "G1", "G2", "G3", "G4", "G5",
        "H2",
        "I3", "I6",
        "J3", "J5", "J6",
        "K12", "K13",
        "M1", "M2", "M4",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T5",
      control_name: "Data Exfiltration",
      control_description:
        "Data-exfiltration channels native to the MCP runtime — HTTP, DNS, headers, clipboard, steganographic payloads.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["A3", "F3", "F7", "G7", "I9", "K18", "O4", "O5", "O6", "O8", "O9", "O10"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T6",
      control_name: "Supply-Chain Compromise",
      control_description:
        "Pre-deployment compromise: malicious or typosquatted packages, manifest confusion, package-registry substitution, GitHub Actions poisoning.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["D5", "D7", "K9", "K10", "L1", "L2", "L5", "L6", "L10"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T7",
      control_name: "Protocol-Level Attacks",
      control_description:
        "Attacks against JSON-RPC and transport: batch abuse, notification flood, session hijacking, protocol downgrade.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["E2", "F4", "I15", "N1", "N2", "N3", "N5", "N6", "N7", "N8", "N10", "N11", "N13", "N15"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T8",
      control_name: "Runtime & Sandbox Escape",
      control_description:
        "Container breakout, socket mounts, privileged capabilities, host filesystem/network exposure.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["K19", "P1", "P2", "P4", "P5", "P6", "P7", "P10", "Q7"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T9",
      control_name: "Multi-Agent Collusion",
      control_description:
        "Patterns that enable (or fail to prevent) multiple agents colluding or propagating injection across an agent mesh.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["F1", "H3", "I13", "J1", "K14", "K15", "Q10"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T10",
      control_name: "Resource Exhaustion",
      control_description:
        "Unbounded recursion, missing timeouts, response bombs, cost amplification that deny service or run up bills.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["E4", "K16", "K17", "I8", "M7", "M8", "P9"],
      unmet_threshold: "medium",
    },
    {
      control_id: "CoSAI-T11",
      control_name: "Model & Weight Tampering",
      control_description:
        "Manipulation of bundled model artifacts, build-time fine-tuning poisoning, or model-card tampering shipped as part of the server.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["K11", "L3", "L8"],
      unmet_threshold: "high",
    },
    {
      control_id: "CoSAI-T12",
      control_name: "Observability Failure",
      control_description:
        "Absent, destructive, or tamperable logging that blinds responders to MCP-layer attacks.",
      source_url: "https://coalitionforsecureai.org/mcp-security/",
      assessor_rule_ids: ["K1", "K2", "K3", "K20", "E3"],
      unmet_threshold: "medium",
    },
  ],
};
