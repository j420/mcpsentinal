import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class EUAIActAgent extends FrameworkAgent {
  readonly id: FrameworkId = "eu_ai_act";
  readonly metadata: FrameworkMetadata = {
    id: "eu_ai_act",
    name: "EU AI Act",
    short_name: "EU AI Act",
    authority: "European Union",
    reference_url: "https://artificialintelligenceact.eu/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    {
      control: "Art.9",
      name: "Article 9 — Risk Management System",
      description:
        "High-risk AI systems must operate within a documented risk management lifecycle that identifies and mitigates foreseeable misuse.",
    },
    {
      control: "Art.12",
      name: "Article 12 — Record Keeping",
      description:
        "High-risk AI systems must automatically record events ('logs') over the system's lifetime to ensure traceability.",
    },
    {
      control: "Art.13",
      name: "Article 13 — Transparency & Information to Users",
      description:
        "Users must be able to interpret system output and understand its capabilities and limitations.",
    },
    {
      control: "Art.14",
      name: "Article 14 — Human Oversight",
      description:
        "High-risk AI systems must be designed so they can be effectively overseen by natural persons during use.",
    },
    {
      control: "Art.15",
      name: "Article 15 — Accuracy, Robustness, Cybersecurity",
      description:
        "High-risk AI systems must achieve appropriate accuracy, robustness, and cybersecurity throughout their lifecycle.",
    },
  ];
}
