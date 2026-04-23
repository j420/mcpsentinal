import type { ComplianceReportRenderer } from "./types.js";

/**
 * Generic JSON renderer. The signed envelope IS the JSON output — pretty
 * printed for human readability while remaining machine-parseable. Shared
 * by all 7 frameworks: the framework-specific content already lives inside
 * the signed payload, so JSON rendering is framework-agnostic.
 */
export const jsonRenderer: ComplianceReportRenderer = {
  format: "json",
  contentType: "application/json; charset=utf-8",
  filenameSuffix: "json",
  render(signed) {
    return JSON.stringify(signed, null, 2);
  },
};
