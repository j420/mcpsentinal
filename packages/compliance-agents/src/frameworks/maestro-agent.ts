import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class MAESTROAgent extends FrameworkAgent {
  readonly id: FrameworkId = "maestro";
  readonly metadata: FrameworkMetadata = {
    id: "maestro",
    name: "MAESTRO Layered Threat Model",
    short_name: "MAESTRO",
    authority: "Cloud Security Alliance",
    reference_url: "https://cloudsecurityalliance.org/research/working-groups/ai-safety/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    { control: "L1", name: "L1 — Foundation Models", description: "Model weights, prompts, fine-tuning provenance." },
    { control: "L2", name: "L2 — Data Operations", description: "Training, retrieval, vector store integrity." },
    { control: "L3", name: "L3 — Agent Frameworks", description: "Reasoning, planning, tool-use surfaces." },
    { control: "L4", name: "L4 — Deployment Infrastructure", description: "Containers, orchestration, network." },
    { control: "L5", name: "L5 — Observability", description: "Logging, tracing, anomaly detection." },
    { control: "L6", name: "L6 — Security/Safety", description: "Human oversight, policy enforcement." },
    { control: "L7", name: "L7 — Agent Ecosystem", description: "Inter-agent trust, shared state, multi-agent attack surfaces." },
  ];
}
