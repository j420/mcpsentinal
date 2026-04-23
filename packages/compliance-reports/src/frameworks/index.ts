import type { FrameworkId } from "../types.js";
import { FRAMEWORK_IDS } from "../types.js";
import { COSAI_MCP } from "./cosai_mcp.js";
import { EU_AI_ACT } from "./eu_ai_act.js";
import { ISO_27001 } from "./iso_27001.js";
import { MAESTRO } from "./maestro.js";
import { MITRE_ATLAS } from "./mitre_atlas.js";
import { OWASP_ASI } from "./owasp_asi.js";
import { OWASP_MCP } from "./owasp_mcp.js";
import type { Framework } from "./types.js";

export type { Framework, FrameworkControl } from "./types.js";

export const FRAMEWORKS: Record<FrameworkId, Framework> = {
  eu_ai_act: EU_AI_ACT,
  iso_27001: ISO_27001,
  owasp_mcp: OWASP_MCP,
  owasp_asi: OWASP_ASI,
  cosai_mcp: COSAI_MCP,
  maestro: MAESTRO,
  mitre_atlas: MITRE_ATLAS,
};

export function getFramework(id: FrameworkId): Framework {
  const f = FRAMEWORKS[id];
  if (!f) {
    // Defensive — FrameworkId union guarantees membership, but we throw an
    // explicit error if someone bypasses the type system.
    throw new Error(`Unknown framework id: ${id as string}`);
  }
  return f;
}

export function getAllFrameworks(): Framework[] {
  return FRAMEWORK_IDS.map((id) => FRAMEWORKS[id]);
}
