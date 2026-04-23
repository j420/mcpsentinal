import type { ControlStatus, OverallStatus } from "../../types.js";

/**
 * Shared status → colour/label mapping consumed by HTML + PDF + (in future)
 * badge renderers. Colours are WCAG AA compliant against a white background.
 */
export interface StatusStyle {
  /** Hex colour (`#RRGGBB`). */
  color: string;
  /** Hex background for chips / pills. */
  background: string;
  /** Short human label rendered in pills. */
  label: string;
  /** Single char glyph for regulators who print in black & white. */
  glyph: string;
}

export const CONTROL_STATUS_STYLING: Record<ControlStatus, StatusStyle> = {
  met: {
    color: "#0b5d1e", // forest green on white = 7.1:1
    background: "#d4efdc",
    label: "Met",
    glyph: "✓", // ✓
  },
  unmet: {
    color: "#8a1f11", // oxblood on white = 7.6:1
    background: "#fbdcd7",
    label: "Unmet",
    glyph: "✗", // ✗
  },
  partial: {
    color: "#7a4a00", // burnt amber on white = 7.1:1
    background: "#fde9c8",
    label: "Partial",
    glyph: "!",
    // NB: amber chosen over yellow for AA contrast.
  },
  not_applicable: {
    color: "#444b52",
    background: "#e4e7ea",
    label: "Not applicable",
    glyph: "–", // –
  },
};

export const OVERALL_STATUS_STYLING: Record<OverallStatus, StatusStyle> = {
  compliant: {
    color: "#0b5d1e",
    background: "#d4efdc",
    label: "Compliant",
    glyph: "✓",
  },
  non_compliant: {
    color: "#8a1f11",
    background: "#fbdcd7",
    label: "Non-compliant",
    glyph: "✗",
  },
  partially_compliant: {
    color: "#7a4a00",
    background: "#fde9c8",
    label: "Partially compliant",
    glyph: "!",
  },
  insufficient_evidence: {
    color: "#444b52",
    background: "#e4e7ea",
    label: "Insufficient evidence",
    glyph: "?",
  },
};

/**
 * Severity → chip styling used inside the evidence table. Kept here so HTML
 * and PDF use identical colour assignments.
 */
export interface SeverityStyle {
  color: string;
  background: string;
  label: string;
}

export const SEVERITY_STYLING: Record<string, SeverityStyle> = {
  critical: { color: "#5c0e04", background: "#f5c7bf", label: "Critical" },
  high: { color: "#8a1f11", background: "#fbdcd7", label: "High" },
  medium: { color: "#7a4a00", background: "#fde9c8", label: "Medium" },
  low: { color: "#114f87", background: "#d2e4f5", label: "Low" },
  informational: { color: "#444b52", background: "#e4e7ea", label: "Info" },
};

export function severityStyle(sev: string): SeverityStyle {
  return SEVERITY_STYLING[sev] ?? SEVERITY_STYLING.informational!;
}
