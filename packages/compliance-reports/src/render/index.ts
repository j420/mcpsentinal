export { htmlRenderer } from "./html-renderer.js";
export { jsonRenderer } from "./json-renderer.js";
export { pdfRenderer } from "./pdf-renderer.js";
export * from "./types.js";
// Side-effect: populate the renderer registry with 21 (format, framework)
// entries on first import of the `render/` subtree.
import "./register-all.js";
