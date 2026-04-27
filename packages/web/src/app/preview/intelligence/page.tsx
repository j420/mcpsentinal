/**
 * Preview /intelligence — placeholder.
 *
 * Eventually the home of Attack Chains, Drift Wall, Lethal Trifecta Map, CVE
 * Wall, and Benchmark — the differentiated data layer surfaced as one
 * navigation slot. For now this stub links to the live /attack-chains page,
 * which is the most-built piece of the future Intelligence section.
 */

import type { Metadata } from "next";
import PlaceholderSlot from "../_components/PlaceholderSlot";

export const metadata: Metadata = {
  title: "Intelligence",
  description: "Kill chains, drift, lethal trifectas, CVE replay corpus.",
};

export default function PreviewIntelligencePage() {
  return (
    <PlaceholderSlot
      label="Intelligence"
      title="The differentiated data layer"
      description="Kill chains, capability drift, cross-config lethal trifectas, the CVE replay corpus, and the competitive benchmark — everything that proves Sentinel measures the ecosystem rather than reasoning about it. Today /attack-chains is built; the rest is in Bucket 6."
      liveHref="/attack-chains"
      liveLabel="Open the live attack-chains page"
      followUp="Bucket 6 #33–#37 — Ecosystem map, Drift Wall, Trifecta Map, CVE Wall, Benchmark"
    />
  );
}
