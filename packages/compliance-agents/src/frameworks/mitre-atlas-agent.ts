import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class MITREATLASAgent extends FrameworkAgent {
  readonly id: FrameworkId = "mitre_atlas";
  readonly metadata: FrameworkMetadata = {
    id: "mitre_atlas",
    name: "MITRE ATLAS",
    short_name: "ATLAS",
    authority: "MITRE",
    reference_url: "https://atlas.mitre.org/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    {
      control: "AML.T0054",
      name: "AML.T0054 — LLM Prompt Injection",
      description:
        "Adversary injects instructions into the LLM via untrusted content in tool descriptions, parameters, or external resources.",
    },
    {
      control: "AML.T0055",
      name: "AML.T0055 — LLM Jailbreak",
      description:
        "Adversary bypasses the model's safety alignment to elicit prohibited behavior.",
    },
    {
      control: "AML.T0056",
      name: "AML.T0056 — LLM Plugin Compromise",
      description:
        "Adversary compromises a tool/plugin the LLM uses, turning it into a launchpad for further attacks.",
    },
    {
      control: "AML.T0057",
      name: "AML.T0057 — LLM Data Leakage",
      description:
        "Sensitive data the LLM has seen is emitted via tool responses, side channels, or memory leaks.",
    },
    {
      control: "AML.T0058",
      name: "AML.T0058 — AI Agent Context Poisoning",
      description:
        "Adversary places content where the agent will later read it, poisoning the reasoning context.",
    },
    {
      control: "AML.T0059",
      name: "AML.T0059 — Memory Manipulation",
      description: "Adversary writes into shared agent memory or vector stores.",
    },
    {
      control: "AML.T0060",
      name: "AML.T0060 — Modify AI Agent Configuration",
      description:
        "Adversary mutates the agent's config (MCP server list, tools, permissions) to install persistence.",
    },
    {
      control: "AML.T0061",
      name: "AML.T0061 — Thread Injection",
      description:
        "Adversary injects messages into a conversation thread to influence subsequent agent decisions.",
    },
  ];
}
