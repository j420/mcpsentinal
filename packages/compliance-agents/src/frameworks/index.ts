/**
 * Framework agent registry. The orchestrator imports this module to get
 * the list of available agents and dispatch on framework id.
 */

import type { FrameworkAgent } from "./base-agent.js";
import type { FrameworkId } from "../types.js";
import { OWASPMCPAgent } from "./owasp-mcp-agent.js";
import { OWASPASIAgent } from "./owasp-asi-agent.js";
import { CoSAIAgent } from "./cosai-agent.js";
import { MAESTROAgent } from "./maestro-agent.js";
import { EUAIActAgent } from "./eu-ai-act-agent.js";
import { MITREATLASAgent } from "./mitre-atlas-agent.js";

const AGENTS: Record<FrameworkId, FrameworkAgent> = {
  owasp_mcp: new OWASPMCPAgent(),
  owasp_asi: new OWASPASIAgent(),
  cosai: new CoSAIAgent(),
  maestro: new MAESTROAgent(),
  eu_ai_act: new EUAIActAgent(),
  mitre_atlas: new MITREATLASAgent(),
};

export function getFrameworkAgent(id: FrameworkId): FrameworkAgent {
  return AGENTS[id];
}

export function getAllFrameworkAgents(): FrameworkAgent[] {
  return Object.values(AGENTS);
}

export {
  OWASPMCPAgent,
  OWASPASIAgent,
  CoSAIAgent,
  MAESTROAgent,
  EUAIActAgent,
  MITREATLASAgent,
};
