import { FrameworkAgent, type CategoryDefinition } from "./base-agent.js";
import type { FrameworkId, FrameworkMetadata } from "../types.js";

export class CoSAIAgent extends FrameworkAgent {
  readonly id: FrameworkId = "cosai";
  readonly metadata: FrameworkMetadata = {
    id: "cosai",
    name: "CoSAI MCP Security Threat Model",
    short_name: "CoSAI",
    authority: "Coalition for Secure AI",
    reference_url: "https://cosai.org/",
  };

  protected readonly categoryDefinitions: CategoryDefinition[] = [
    { control: "T1", name: "T1 — Identity & Access", description: "Authentication, scope, lifecycle." },
    { control: "T2", name: "T2 — Authorization", description: "Policy enforcement at the tool boundary." },
    { control: "T3", name: "T3 — Code Vulnerabilities", description: "Insecure code in the MCP server itself." },
    { control: "T4", name: "T4 — Prompt & Tool Manipulation", description: "Instructions or annotations crafted to mislead the LLM." },
    { control: "T5", name: "T5 — Data Boundary", description: "Sensitive data crossing trust zones via tool responses." },
    { control: "T6", name: "T6 — Supply Chain", description: "Build, package, registry attacks." },
    { control: "T7", name: "T7 — Transport Security", description: "TLS, session tokens, replay protection." },
    { control: "T8", name: "T8 — Runtime Sandbox", description: "Container, namespace, capability enforcement." },
    { control: "T9", name: "T9 — Multi-Agent Trust", description: "Cross-agent message authenticity & shared state hygiene." },
    { control: "T10", name: "T10 — Resource Exhaustion", description: "DoS via infinite loops, unbounded queries, large payloads." },
    { control: "T11", name: "T11 — Build Integrity", description: "CI/CD pipeline compromise & artifact provenance." },
    { control: "T12", name: "T12 — Audit & Forensics", description: "Logging completeness and tamper-resistance." },
  ];
}
