/**
 * Stable display map for framework cross-walk badges.
 *
 * The backend (`framework_controls[].framework_id`) ships the full canonical
 * id; the UI maps to a short, badge-density-friendly label. This file is the
 * single source of truth — extend here, never inline in a component.
 *
 * Cluster B part 3 (Invention #8): consumed by FindingsEvidenceTab cross-walk.
 * Cluster C cleanup will fold HonestGaps' framework-name strings here too.
 */

export type FrameworkId =
  | "eu_ai_act"
  | "iso_27001"
  | "owasp_mcp"
  | "owasp_asi"
  | "cosai_mcp"
  | "maestro"
  | "mitre_atlas";

export const FRAMEWORK_SHORT_LABELS: Record<FrameworkId, string> = {
  eu_ai_act: "EU AI Act",
  iso_27001: "ISO 27001",
  owasp_mcp: "OWASP MCP",
  owasp_asi: "OWASP ASI",
  cosai_mcp: "CoSAI MCP",
  maestro: "MAESTRO",
  mitre_atlas: "MITRE ATLAS",
};
