import type { Framework } from "./types.js";

/**
 * OWASP Agentic Applications Security Top 10 (December 2025). Mapping
 * sourced from `agent_docs/detection-rules.md` Agentic coverage table.
 * ASI10 (Agentic Data Poisoning) has zero static-analysis assessors in
 * the current rule set — declared explicitly below.
 */
export const OWASP_ASI: Framework = {
  id: "owasp_asi",
  name: "OWASP Agentic Applications Security Top 10",
  version: "2025-12",
  last_updated: "2026-04-23",
  source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
  controls: [
    {
      control_id: "ASI01",
      control_name: "Agent Goal Hijack",
      control_description:
        "Manipulation of an agent's working objective via injected descriptions, initialize metadata, or authority-claiming content, diverting it from the operator's intent.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["A1", "A7", "A9", "G2", "G5", "H2", "I3", "I6", "J5", "J6"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI02",
      control_name: "Tool Misuse",
      control_description:
        "Agent is induced to call the right tool the wrong way, or a wrong tool, because of schema ambiguity, deceptive annotations, or coercive descriptions.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["B2", "B7", "C1", "C9", "C16", "I1", "I2", "I12", "J2", "K12", "K13"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI03",
      control_name: "Identity & Privilege Abuse",
      control_description:
        "OAuth implementation flaws, credential sprawl, long-lived tokens, and cross-boundary credential propagation allow attackers to impersonate agents or elevate privilege.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["C8", "E1", "H1", "I11", "I12", "J1", "K6", "K7", "K8"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI04",
      control_name: "Agentic Supply Chain",
      control_description:
        "Compromise of tool descriptions, prompt packs, model weights, or MCP server packages at the supply-chain layer.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: [
        "D1", "D3", "D5", "D7",
        "F5",
        "I5",
        "J7",
        "K9", "K10", "K11",
        "L1", "L2", "L3", "L5", "L6", "L7", "L8", "L9", "L10", "L11", "L12", "L13", "L14", "L15",
        "Q4", "Q13",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI05",
      control_name: "Unexpected Code Execution",
      control_description:
        "Agent or server executes attacker-supplied code via eval, deserialization, template rendering, or shell substitution.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["C1", "C12", "C13", "C16", "J2", "J7"],
      unmet_threshold: "critical",
    },
    {
      control_id: "ASI06",
      control_name: "Memory & Context Poisoning",
      control_description:
        "Persistent or transient contamination of agent memory, vector stores, tool descriptions, or init fields such that future agent sessions behave maliciously.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["F6", "G1", "G4", "H2", "H3", "I3", "J3", "J5"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI07",
      control_name: "Insecure Inter-Agent Communication",
      control_description:
        "Cross-agent messages propagate prompt injections, credentials, or side-effects without trust-boundary enforcement.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["F1", "F7", "H3", "I13", "J1", "K14", "K15"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI08",
      control_name: "Agentic Denial of Service",
      control_description:
        "Resource-exhaustion attacks that exploit unbounded reasoning loops, cost amplification, response bombs, or recursion without depth limits.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["E4", "K16", "K17", "K19", "M7", "M8", "P9"],
      unmet_threshold: "medium",
    },
    {
      control_id: "ASI09",
      control_name: "Human Oversight Bypass",
      control_description:
        "Patterns that skip, fatigue, or preempt the human-in-the-loop: auto-approve toggles, confirmation prompts tucked behind long tool lists, trust inheritance.",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      assessor_rule_ids: ["K4", "K5", "G5", "I12", "I16", "M5"],
      unmet_threshold: "high",
    },
    {
      control_id: "ASI10",
      control_name: "Agentic Data Poisoning",
      control_description:
        "Tainted data injected into an agent's training, fine-tuning, or retrieval corpus. Distinct from runtime context poisoning (ASI06).",
      source_url: "https://owasp.org/www-project-agentic-applications-top-10/",
      // NO ASSESSOR RULE — MCP Sentinel scans only deployed MCP servers,
      // not the upstream training pipelines where data poisoning occurs.
      // Documented gap for Phase 6.
      assessor_rule_ids: [],
      unmet_threshold: "high",
    },
  ],
};
