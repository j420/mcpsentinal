/**
 * Preview /scanner — placeholder.
 *
 * The live /scanner page is already in good shape; the proposed change is
 * trimming three duplicate sections (Score Interpretation, Detection
 * Coverage, Other Clients) which all duplicate content already in Methodology
 * or About. Trimming is a low-risk follow-up; for now this stub points to
 * the live page.
 */

import type { Metadata } from "next";
import PlaceholderSlot from "../_components/PlaceholderSlot";

export const metadata: Metadata = {
  title: "Scanner",
  description: "npx mcp-sentinel-scanner — install, expected output, safety.",
};

export default function PreviewScannerPage() {
  return (
    <PlaceholderSlot
      label="Scanner"
      title="Run Sentinel against your own MCP servers"
      description="npx mcp-sentinel-scanner exposes scan_server, scan_endpoint, and list_rules as MCP tools any client (Claude Desktop, Cursor, VS Code, Windsurf) can call. The live page already covers install, example output, and safety — the proposed trim is removing the three sections that duplicate Methodology."
      liveHref="/scanner"
      liveLabel="Open the live scanner page"
      followUp="Bucket 3 #18 — Trim duplicate sections in /scanner"
    />
  );
}
