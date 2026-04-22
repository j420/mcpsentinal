/**
 * Edge-of-spec bucket. 65 fixtures crafted to stress-test the false-positive
 * boundary of specific rules. At least one fixture per active category
 * (A–Q). Each fixture's `why_benign` names the rule(s) it stresses.
 */
import type { BenignFixture } from "../types.js";

export const edgeOfSpecFixtures: readonly BenignFixture[] = [];
