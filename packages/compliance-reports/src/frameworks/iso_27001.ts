import type { Framework } from "./types.js";

/**
 * ISO/IEC 27001:2022 Annex A controls cited by detection-rules.md K-category
 * rules + additional controls surfaced by non-K rules. Subset only —
 * controls without assessor rules in the current rule set are intentionally
 * excluded from this registry (regulators expect only the subset we actually
 * assess).
 */
export const ISO_27001: Framework = {
  id: "iso_27001",
  name: "ISO/IEC 27001",
  version: "2022",
  last_updated: "2026-04-23",
  source_url: "https://www.iso.org/standard/82875.html",
  controls: [
    {
      control_id: "A.5.14",
      control_name: "Information Transfer",
      control_description:
        "Rules, procedures, or agreements for information transfer within the organization and between the organization and external parties must be established, with controls to protect data crossing trust boundaries.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K18", "F3", "F7", "G7"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.5.15",
      control_name: "Access Control",
      control_description:
        "Rules for controlling physical and logical access to information and information-processing facilities must be established, documented, and reviewed, including least-privilege defaults.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K6", "E1", "I11"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.5.17",
      control_name: "Authentication Information",
      control_description:
        "Allocation and management of authentication information must be controlled, including password strength, credential rotation, and constraints on credential sharing across boundaries.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K8", "C5", "L9"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.5.18",
      control_name: "Access Rights",
      control_description:
        "Access rights to information and assets must be provisioned, reviewed, modified, and removed in accordance with topic-specific policy and rules for access control.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K6"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.5.20",
      control_name: "Addressing Information Security within Supplier Agreements",
      control_description:
        "Relevant information-security requirements must be established and agreed with each supplier, including code-signing, SBOM, and integrity-verification obligations for software suppliers.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K11", "L3", "L5", "L7"],
      unmet_threshold: "medium",
    },
    {
      control_id: "A.5.21",
      control_name: "Managing Information Security in the ICT Supply Chain",
      control_description:
        "Processes and procedures must be defined and implemented to manage information-security risks associated with the ICT products and services supply chain.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K10", "D5", "D7", "L1", "L2", "L6", "L8", "L10", "L12", "L13", "L15"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.8.15",
      control_name: "Logging",
      control_description:
        "Logs that record activities, exceptions, faults, and other relevant events must be produced, stored, protected, and analysed. Log integrity and sufficient context are mandatory.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K1", "K2", "K3", "K20", "E3"],
      unmet_threshold: "medium",
    },
    {
      control_id: "A.8.22",
      control_name: "Segregation of Networks",
      control_description:
        "Groups of information services, users, and information systems must be segregated in the organization's networks; runtime sandboxing and container isolation implement this at process level.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K19", "P1", "P2", "P7", "P10"],
      unmet_threshold: "high",
    },
    {
      control_id: "A.8.24",
      control_name: "Use of Cryptography",
      control_description:
        "Rules for the effective use of cryptography, including key management, algorithm selection, and cryptographic control lifecycle, must be defined and implemented.",
      source_url: "https://www.iso.org/standard/82875.html",
      assessor_rule_ids: ["K7", "C14", "C15", "D6", "P4", "P8"],
      unmet_threshold: "high",
    },
  ],
};
