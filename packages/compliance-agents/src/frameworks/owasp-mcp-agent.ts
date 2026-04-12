import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class OWASPMCPAgent extends FrameworkAgent {
  readonly id: FrameworkId = "owasp_mcp";
  readonly metadata: FrameworkMetadata = {
    id: "owasp_mcp",
    name: "OWASP MCP Top 10",
    short_name: "OWASP MCP",
    authority: "OWASP Foundation",
    reference_url: "https://owasp.org/www-project-mcp-top-ten/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    {
      control: "MCP01",
      name: "MCP01 — Prompt Injection",
      description:
        "Untrusted content reaching the LLM with the same trust level as user instructions.",
    },
    {
      control: "MCP02",
      name: "MCP02 — Tool Poisoning",
      description:
        "A tool's metadata, schema, or annotations are crafted to manipulate the AI's tool selection or argument-filling.",
    },
    {
      control: "MCP03",
      name: "MCP03 — Command Injection",
      description:
        "User or untrusted input flows into shell, eval, or subprocess sinks without sanitization.",
    },
    {
      control: "MCP04",
      name: "MCP04 — Data Exfiltration",
      description: "Sensitive data is read by one tool and emitted by another.",
    },
    {
      control: "MCP05",
      name: "MCP05 — Privilege Escalation",
      description:
        "Capability elevation via tool composition, missing authorization checks, or policy gaps.",
    },
    {
      control: "MCP06",
      name: "MCP06 — Excessive Permissions",
      description:
        "Server or tool requests broader scope than the intended use case requires.",
    },
    {
      control: "MCP07",
      name: "MCP07 — Insecure Configuration",
      description: "Wildcard CORS, weak transport, default credentials, debug endpoints.",
    },
    {
      control: "MCP08",
      name: "MCP08 — Dependency Vulnerabilities",
      description: "Known-CVE dependencies, abandoned packages, weak crypto libs.",
    },
    {
      control: "MCP09",
      name: "MCP09 — Logging & Monitoring",
      description: "Audit trail is missing, partial, mutable, or destroyable.",
    },
    {
      control: "MCP10",
      name: "MCP10 — Supply Chain",
      description:
        "Typosquatting, post-install hooks, registry confusion, manifest mismatches.",
    },
  ];
}
