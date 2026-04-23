/**
 * Side-effect module. Importing this file populates the renderer registry
 * with 21 entries (3 formats × 7 frameworks). Each format uses a single
 * generic implementation — framework-specific content is already present
 * inside the signed report, so the renderers are framework-agnostic and
 * get registered seven times each.
 */
import "../badges/types.js";

import type { FrameworkId } from "../types.js";
import { htmlRenderer } from "./html-renderer.js";
import { jsonRenderer } from "./json-renderer.js";
import { pdfRenderer } from "./pdf-renderer.js";
import { registerRenderer } from "./types.js";

const FRAMEWORKS: FrameworkId[] = [
  "eu_ai_act",
  "iso_27001",
  "owasp_mcp",
  "owasp_asi",
  "cosai_mcp",
  "maestro",
  "mitre_atlas",
];

for (const framework of FRAMEWORKS) {
  registerRenderer("html", framework, htmlRenderer);
  registerRenderer("json", framework, jsonRenderer);
  registerRenderer("pdf", framework, pdfRenderer);
}
