/**
 * Preview /about — placeholder.
 *
 * The live /about page is 534 lines doing four jobs (mission, pipeline, full
 * rule list, OWASP mapping). The proposed split: keep mission and principles
 * here, move rules/scoring/frameworks to /preview/methodology. For now this
 * stub points to the live page.
 */

import type { Metadata } from "next";
import PlaceholderSlot from "../_components/PlaceholderSlot";

export const metadata: Metadata = {
  title: "About",
  description: "Mission, principles, and what Sentinel is for.",
};

export default function PreviewAboutPage() {
  return (
    <PlaceholderSlot
      label="About"
      title="Mission and principles"
      description="What Sentinel is for, who it serves, and the architecture principles that govern it. The live /about page currently mixes mission with rule lists, OWASP mappings, and the scoring formula; the proposed split keeps mission here and folds the rest into Methodology."
      liveHref="/about"
      liveLabel="Open the live about page"
      followUp="Bucket 3 #17 — Split /about into mission + methodology"
    />
  );
}
