import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class OWASPASIAgent extends FrameworkAgent {
  readonly id: FrameworkId = "owasp_asi";
  readonly metadata: FrameworkMetadata = {
    id: "owasp_asi",
    name: "OWASP Agentic Applications Top 10",
    short_name: "OWASP ASI",
    authority: "OWASP Foundation",
    reference_url: "https://owasp.org/www-project-agentic-ai-top-10/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    {
      control: "ASI01",
      name: "ASI01 — Agent Goal Hijack",
      description: "An attacker redirects the agent's objective via injected instructions.",
    },
    {
      control: "ASI02",
      name: "ASI02 — Tool Misuse",
      description: "Agent uses a legitimate tool for an unintended destructive purpose.",
    },
    {
      control: "ASI03",
      name: "ASI03 — Identity & Privilege Abuse",
      description: "Credential or scope misuse across trust boundaries.",
    },
    {
      control: "ASI04",
      name: "ASI04 — Agentic Supply Chain",
      description: "Malicious package, post-install hook, or registry substitution.",
    },
    {
      control: "ASI05",
      name: "ASI05 — Unexpected Code Execution",
      description: "Untrusted input reaches an eval/exec sink in the agent runtime.",
    },
    {
      control: "ASI06",
      name: "ASI06 — Memory & Context Poisoning",
      description: "Attacker writes into shared memory the agent later trusts.",
    },
    {
      control: "ASI07",
      name: "ASI07 — Insecure Inter-Agent Communication",
      description: "Trust between agents is implicit, not enforced.",
    },
    {
      control: "ASI08",
      name: "ASI08 — Agentic DoS",
      description: "Unbounded recursion, missing depth limits, runaway loops.",
    },
    {
      control: "ASI09",
      name: "ASI09 — Human Oversight Bypass",
      description: "Confirmation gate is missing, auto-approved, or pre-approved.",
    },
    {
      control: "ASI10",
      name: "ASI10 — Agentic Data Poisoning",
      description: "Attacker injects content the agent treats as ground truth.",
    },
  ];
}
