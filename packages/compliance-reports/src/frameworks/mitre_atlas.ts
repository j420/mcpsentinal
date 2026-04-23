import type { Framework } from "./types.js";

/**
 * MITRE ATLAS v5.0 AI techniques cited in `agent_docs/detection-rules.md`
 * coverage tables. ATLAS is an adversarial TTP taxonomy, not a prescriptive
 * control framework; our "control_description" fields summarise the
 * technique and our assessor rules are those that deterministically detect
 * artifacts of the technique in a deployed MCP server.
 */
export const MITRE_ATLAS: Framework = {
  id: "mitre_atlas",
  name: "MITRE ATLAS",
  version: "v5.0",
  last_updated: "2026-04-23",
  source_url: "https://atlas.mitre.org/",
  controls: [
    {
      control_id: "AML.T0054",
      control_name: "LLM Prompt Injection",
      control_description:
        "Adversary crafts input that subverts the LLM's intended instructions. Parent technique covering direct and indirect prompt-injection variants.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0054",
      assessor_rule_ids: [
        "A1", "A5", "A7", "A9",
        "B5",
        "G2", "G3", "G5",
        "H2",
        "I3", "I6",
        "J3", "J5",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0054.001",
      control_name: "Indirect Prompt Injection",
      control_description:
        "Sub-technique: adversary-controlled content reaches the LLM indirectly via tools that ingest external data (web scraping, email, issue tracker content).",
      source_url: "https://atlas.mitre.org/techniques/AML.T0054/001",
      assessor_rule_ids: ["G1", "F6", "I3", "J5"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0054.002",
      control_name: "Direct Prompt Injection",
      control_description:
        "Sub-technique: adversary directly provides injected content to the LLM — first-party tool descriptions, init fields, schema fields.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0054/002",
      assessor_rule_ids: ["A1", "A9", "H2"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0055",
      control_name: "Unsecured Credentials",
      control_description:
        "Adversary obtains credentials from MCP server code or configuration — hardcoded secrets, weak auth, cross-boundary credential sharing.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0055",
      assessor_rule_ids: ["C5", "C8", "E1", "H1", "I11", "I12", "K6", "K7", "K8", "L9"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0057",
      control_name: "LLM Data Leakage",
      control_description:
        "LLM emits sensitive data (credentials, PII, proprietary code) in its response. Covers exfiltration via tool-response shaping and elicitation abuse.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0057",
      assessor_rule_ids: ["A3", "F3", "F7", "G7", "I9", "J4", "O4", "O5", "O9", "O10"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0058",
      control_name: "AI Agent Context Poisoning",
      control_description:
        "Adversary contaminates the agent's reasoning context — tool descriptions, memory, init fields, retrieved content — so future queries behave maliciously.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0058",
      assessor_rule_ids: ["G4", "H2", "I3", "I6", "J3", "J5"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0059",
      control_name: "Memory Manipulation",
      control_description:
        "Adversary writes to persistent agent memory (vector stores, scratchpads, shared state) to achieve cross-session persistence.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0059",
      assessor_rule_ids: ["F6", "H3", "J1"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0060",
      control_name: "Modify AI Agent Configuration",
      control_description:
        "Adversary writes to an agent's on-disk configuration (.claude/, .cursor/, ~/.mcp.json) to change which servers the agent trusts.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0060",
      assessor_rule_ids: ["J1", "L4", "L11", "Q4"],
      unmet_threshold: "critical",
    },
    {
      control_id: "AML.T0061",
      control_name: "Thread Injection",
      control_description:
        "Adversary injects content into an ongoing conversational thread (multi-turn setup, session hijack, reconnection injection).",
      source_url: "https://atlas.mitre.org/techniques/AML.T0061",
      assessor_rule_ids: ["G3", "G5", "H2", "I15", "N6"],
      unmet_threshold: "high",
    },
    {
      control_id: "AML.T0086",
      control_name: "Agent Tool Exfiltration",
      control_description:
        "Adversary uses the agent's tool-calling capability itself as an exfiltration channel — causing the agent to call tools that transmit data externally.",
      source_url: "https://atlas.mitre.org/techniques/AML.T0086",
      assessor_rule_ids: ["F7", "G7", "I13", "K14", "K18"],
      unmet_threshold: "high",
    },
  ],
};
