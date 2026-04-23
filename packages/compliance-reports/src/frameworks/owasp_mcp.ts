import type { Framework } from "./types.js";

/**
 * OWASP MCP Top 10 — coverage sourced from `agent_docs/detection-rules.md`
 * "OWASP MCP Top 10 Coverage" section. Every category has at least one
 * assessor rule; gaps are explicit (none in this framework as of 2026-04-23).
 */
export const OWASP_MCP: Framework = {
  id: "owasp_mcp",
  name: "OWASP MCP Top 10",
  version: "2025",
  last_updated: "2026-04-23",
  source_url: "https://owasp.org/www-project-mcp-top-10/",
  controls: [
    {
      control_id: "MCP01",
      control_name: "Prompt Injection",
      control_description:
        "Attacker-controlled content delivered through MCP server descriptions, parameters, resources, prompts, or initialize metadata that hijacks agent reasoning. Includes direct and indirect injection.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: [
        "A1", "A5", "A7", "A8", "A9",
        "B5",
        "F1", "F6",
        "G1", "G2", "G3", "G4", "G5",
        "H2", "H3",
        "I3", "I6", "I7",
        "J3", "J5", "J6",
        "N4", "N9", "N12",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP02",
      control_name: "Tool Poisoning",
      control_description:
        "Tools that misrepresent their behaviour through deceptive names, annotations, namespace squatting, homoglyphs, or time-based drift (rug pulls).",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: [
        "A2", "A4", "A6",
        "F2", "F5",
        "G6",
        "I1", "I2", "I5", "I16",
        "J5", "J6",
        "K12", "K13",
        "L15",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP03",
      control_name: "Command Injection",
      control_description:
        "Server code that executes shell commands, system calls, or git operations built from attacker-controlled input without sanitisation.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: ["C1", "C9", "C13", "C16", "J2", "J7"],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP04",
      control_name: "Data Exfiltration",
      control_description:
        "Server features that permit sensitive data to leave the trust boundary via HTTP, DNS, headers, URIs, or covert channels.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: [
        "A3",
        "F1", "F3", "F7",
        "G7",
        "I9", "I13",
        "K18",
        "O4", "O5", "O6", "O8", "O9", "O10",
        "P3",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP05",
      control_name: "Privilege Escalation",
      control_description:
        "Vertical privilege increases via JWT confusion, deserialization, evaluation of untrusted input, OAuth scope widening, or capability escalation post-initialization.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: ["C2", "C8", "C10", "C12", "I4", "I12", "J1"],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP06",
      control_name: "Excessive Permissions",
      control_description:
        "Tools or roots claiming broader filesystem, network, or credential access than required for their stated function.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: ["A2", "B3", "B7", "E4", "F2", "I11", "I16"],
      unmet_threshold: "medium",
    },
    {
      control_id: "MCP07",
      control_name: "Insecure Configuration",
      control_description:
        "Servers shipped with insecure defaults: no authentication, wildcard CORS, HTTP transport, weak session tokens, disabled TLS validation, empty sandboxes.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: [
        "B6",
        "C7", "C8", "C11", "C14", "C15",
        "D6",
        "E1", "E2",
        "I15",
        "J4",
      ],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP08",
      control_name: "Dependency Vulnerabilities",
      control_description:
        "Known-CVE, abandoned, malicious, or typosquatted dependencies shipped with the server.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: ["D1", "D2", "D3", "D4", "D5", "D6", "D7"],
      unmet_threshold: "high",
    },
    {
      control_id: "MCP09",
      control_name: "Logging & Monitoring Failures",
      control_description:
        "Absent, insufficient, or tamperable audit logging that prevents incident detection and response.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: ["C6", "E3", "K1", "K2", "K3", "K20"],
      unmet_threshold: "medium",
    },
    {
      control_id: "MCP10",
      control_name: "Supply Chain Compromise",
      control_description:
        "Compromise of the build, publish, or distribution pipeline upstream of the server — including CI/CD token theft, build-artifact tampering, and manifest confusion.",
      source_url: "https://owasp.org/www-project-mcp-top-10/",
      assessor_rule_ids: [
        "A4", "D3", "D5", "D7",
        "F5",
        "I5",
        "J7",
        "K9", "K10", "K11",
        "L1", "L2", "L3", "L4", "L5", "L6", "L7", "L8", "L9", "L10", "L11", "L12", "L13", "L14", "L15",
        "Q4", "Q13",
      ],
      unmet_threshold: "high",
    },
  ],
};
