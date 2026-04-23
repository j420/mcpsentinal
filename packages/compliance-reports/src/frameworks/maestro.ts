import type { Framework } from "./types.js";

/**
 * MAESTRO Multi-Agent Threat Model (CSA, February 2025). Seven layers
 * L1–L7. Mapping derived from `agent_docs/detection-rules.md` plus
 * framework-registry.yaml cross-references. L1 (model security) and L2
 * (data pipeline) have thin coverage because MCP Sentinel operates on
 * deployed MCP servers, not model training infrastructure.
 */
export const MAESTRO: Framework = {
  id: "maestro",
  name: "MAESTRO Multi-Agent Threat Model",
  version: "2025-02",
  last_updated: "2026-04-23",
  source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
  controls: [
    {
      control_id: "L1",
      control_name: "Foundation Models",
      control_description:
        "Threats against model weights, tokenizer, and reasoning — prompt extraction, reasoning-chain manipulation, special-token injection aimed at a specific model.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: ["M1", "M2", "M4", "M9"],
      unmet_threshold: "high",
    },
    {
      control_id: "L2",
      control_name: "Data Operations",
      control_description:
        "Training-data, RAG corpus, and context-pipeline threats. In the MCP Sentinel context this covers tool-response contamination and cross-trust-boundary data flows that feed agent retrieval.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: ["F3", "F7", "G7", "K18"],
      unmet_threshold: "high",
    },
    {
      control_id: "L3",
      control_name: "Agent Framework & Orchestration",
      control_description:
        "Threats at the agent framework layer — prompt injection, tool-description manipulation, tool-output poisoning, schema poisoning that hijacks agent planning.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: [
        "A1", "A5", "A7", "A8", "A9",
        "B5",
        "G1", "G2", "G3", "G4", "G5",
        "H2",
        "I3", "I6",
        "J3", "J5", "J6",
        "K11", "K13",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "L4",
      control_name: "Deployment Infrastructure",
      control_description:
        "Runtime infrastructure: containers, transport, TLS, network isolation, sandbox enforcement, supply-chain provenance at deploy time.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: [
        "E2",
        "I15",
        "K16", "K17", "K19",
        "L3",
        "P1", "P2", "P4", "P5", "P6", "P7", "P8", "P9", "P10",
        "Q3", "Q7",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "L5",
      control_name: "Evaluation & Observability",
      control_description:
        "Logging, monitoring, telemetry — the control plane regulators rely on for incident response. MAESTRO treats missing observability as a high-risk control failure.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: ["K1", "K2", "K3", "K20", "E3"],
      unmet_threshold: "medium",
    },
    {
      control_id: "L6",
      control_name: "Compliance & Governance",
      control_description:
        "Human-oversight controls, consent mechanics, auth/identity lifecycle, trust delegation. The governance boundary.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: ["K4", "K5", "I12", "Q15", "H1", "K6", "K7"],
      unmet_threshold: "high",
    },
    {
      control_id: "L7",
      control_name: "Agent Ecosystem",
      control_description:
        "Cross-agent threats at the ecosystem level — inter-agent messaging, shared memory, config poisoning, lethal trifecta distributed across multiple servers.",
      source_url: "https://cloudsecurityalliance.org/artifacts/maestro",
      assessor_rule_ids: ["F1", "F6", "F7", "H3", "I13", "J1", "K8", "K14", "K15", "Q10"],
      unmet_threshold: "high",
    },
  ],
};
