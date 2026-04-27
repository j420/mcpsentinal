/**
 * Preview /ecosystem — placeholder.
 *
 * The full Ecosystem screen (capability × risk map, weekly delta, severity
 * breakdown, recently-discovered) is a later PR. For now this slot links to
 * the existing live /dashboard page which already serves the same purpose
 * unscoped from the navigation.
 */

import type { Metadata } from "next";
import PlaceholderSlot from "../_components/PlaceholderSlot";

export const metadata: Metadata = {
  title: "Ecosystem",
  description: "Live security posture across every scanned MCP server.",
};

export default function PreviewEcosystemPage() {
  return (
    <PlaceholderSlot
      label="Ecosystem"
      title="Live posture across every scanned server"
      description="Category breakdown, severity distribution, scan coverage, and the recently-discovered feed. The live equivalent already exists at /dashboard but is missing from the navigation. Promoting it into the IA is the next PR."
      liveHref="/dashboard"
      liveLabel="Open the live dashboard"
      followUp="Bucket 6 #33 — Ecosystem Map (capability × risk plot, weekly delta sparklines)"
    />
  );
}
