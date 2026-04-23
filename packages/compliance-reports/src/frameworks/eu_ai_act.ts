import type { Framework } from "./types.js";

/**
 * EU AI Act (Regulation 2024/1689). Article mappings derived from
 * `agent_docs/detection-rules.md` + `rules/framework-registry.yaml`.
 * Enforcement for high-risk AI systems begins August 2026.
 */
export const EU_AI_ACT: Framework = {
  id: "eu_ai_act",
  name: "EU AI Act",
  version: "2024/1689",
  last_updated: "2026-04-23",
  source_url: "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689",
  controls: [
    {
      control_id: "Art.9",
      control_name: "Risk Management System",
      control_description:
        "High-risk AI providers must establish, implement, and maintain a risk management system covering the entire lifecycle, including analysis of reasonably foreseeable misuse and supply-chain risk.",
      source_url: "https://artificialintelligenceact.eu/article/9/",
      assessor_rule_ids: [
        "D1", "D2", "D3", "D4", "D5", "D6", "D7",
        "K9", "K10", "K11",
        "L1", "L2", "L3", "L5", "L6", "L7", "L8", "L10", "L12", "L13",
        "Q4", "Q13",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "Art.12",
      control_name: "Record-Keeping",
      control_description:
        "High-risk AI systems must automatically record events ('logs') over the system lifetime to ensure traceability of the system's functioning appropriate for the intended purpose.",
      source_url: "https://artificialintelligenceact.eu/article/12/",
      assessor_rule_ids: ["K1", "K2", "K3", "K20", "E3"],
      unmet_threshold: "medium",
    },
    {
      control_id: "Art.13",
      control_name: "Transparency & Provision of Information to Deployers",
      control_description:
        "High-risk AI systems must be sufficiently transparent to enable deployers to interpret the system's output appropriately, including capabilities, limitations, and the conditions of intended use.",
      source_url: "https://artificialintelligenceact.eu/article/13/",
      assessor_rule_ids: [
        "A2", "A4", "A6", "A8",
        "F2", "F5",
        "G6",
        "I1", "I2", "I5", "I16",
        "K12", "K13",
        "L15",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "Art.14",
      control_name: "Human Oversight",
      control_description:
        "High-risk AI systems must be designed so that they can be effectively overseen by natural persons during use. Covers the ability to fully understand, monitor, and intervene in the system's operation.",
      source_url: "https://artificialintelligenceact.eu/article/14/",
      assessor_rule_ids: ["K4", "K5", "I12", "M5", "M6", "Q15", "H3", "F1", "F6", "J1", "K14", "K15", "Q10"],
      unmet_threshold: "high",
    },
    {
      control_id: "Art.15",
      control_name: "Accuracy, Robustness, and Cybersecurity",
      control_description:
        "High-risk AI systems must achieve appropriate levels of accuracy, robustness, and cybersecurity throughout their lifecycle. Covers resilience against errors, faults, and adversarial manipulation.",
      source_url: "https://artificialintelligenceact.eu/article/15/",
      assessor_rule_ids: [
        "A1", "A3", "A5", "A7", "A9",
        "B1", "B2", "B3", "B4", "B5", "B6", "B7",
        "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9",
        "C10", "C11", "C12", "C13", "C14", "C15", "C16",
        "E1", "E2", "E4",
        "F3", "F4", "F7",
        "G1", "G2", "G3", "G4", "G5", "G7",
        "H1", "H2",
        "I3", "I4", "I6", "I7", "I8", "I9", "I10", "I11", "I13", "I15",
        "J2", "J3", "J4", "J5", "J6", "J7",
        "K6", "K7", "K8", "K16", "K17", "K18", "K19",
        "L4", "L9", "L11", "L14",
        "M1", "M2", "M4", "M7", "M8", "M9",
        "N1", "N2", "N3", "N4", "N5", "N6", "N7", "N8", "N9", "N10", "N11", "N12", "N13", "N14", "N15",
        "O4", "O5", "O6", "O8", "O9", "O10",
        "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10",
        "Q3", "Q6", "Q7", "Q10", "Q15",
      ],
      unmet_threshold: "high",
    },
  ],
};
