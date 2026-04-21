/**
 * A7 — Verification steps.
 *
 * Every finding emits reviewer-actionable steps targeting a specific
 * tool field so an auditor can reproduce the observation byte-for-byte.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { A7FieldAnalysis } from "./gather.js";

function classSummary(analysis: A7FieldAnalysis): string {
  return analysis.classes_seen.join(", ");
}

export function nameFieldVerificationSteps(
  toolName: string,
  analysis: A7FieldAnalysis,
): VerificationStep[] {
  return [
    {
      step_type: "inspect-description",
      instruction:
        `Hex-dump the tool name (e.g. with 'xxd' or 'unicode --characters') and ` +
        `list every codepoint. Any codepoint in these ranges is invisible in a ` +
        `terminal and must not appear in a tool identifier: ` +
        `U+200B–U+200D (zero-width), U+202A–U+202E (bidi override), ` +
        `U+2060, U+FEFF (joiners/BOM), U+00AD (soft hyphen), ` +
        `U+FE00–U+FE0F (variation selectors), U+E0000–U+E007F (tag chars).`,
      target: `tool:${toolName}:name`,
      expected_observation:
        `${analysis.hits.length} invisible codepoint(s) observed at positions ` +
        `${analysis.hits.map((h) => h.position).join(", ")}. Classes: ${classSummary(analysis)}.`,
    },
    {
      step_type: "compare-baseline",
      instruction:
        `Strip every codepoint listed above from the tool name and compare the ` +
        `cleaned string with the original. If the cleaned string matches a ` +
        `known legitimate tool, the invisible insertion is a shadow-tool attack. ` +
        `If the cleaned string is unchanged, the invisible chars are being used ` +
        `to smuggle a different codepoint sequence past exact-match filters.`,
      target: `tool:${toolName}:name`,
      expected_observation:
        `Cleaned name differs from or collides with a legitimate tool identifier.`,
    },
  ];
}

export function descriptionFieldVerificationSteps(
  toolName: string,
  analysis: A7FieldAnalysis,
): VerificationStep[] {
  const steps: VerificationStep[] = [
    {
      step_type: "inspect-description",
      instruction:
        `Hex-dump the tool description and locate codepoints in the invisible / ` +
        `zero-width / bidi / tag ranges. Record their positions — if positions ` +
        `are NOT adjacent to emoji codepoints, the characters have no ` +
        `legitimate presentational role.`,
      target: `tool:${toolName}:description`,
      expected_observation:
        `${analysis.hits.length} invisible codepoint(s) observed. Classes: ${classSummary(analysis)}.`,
    },
  ];

  if (analysis.hidden_tag_message) {
    steps.push({
      step_type: "inspect-description",
      instruction:
        `Extract every U+E0020–U+E007E codepoint from the description and ` +
        `subtract 0xE0000 from each to map back to the ASCII range. The ` +
        `result is a hidden ASCII message that is invisible in every ` +
        `renderer but readable by the LLM. Verify whether the decoded text ` +
        `contains instructions, URLs, or directives.`,
      target: `tool:${toolName}:description (tag characters)`,
      expected_observation:
        `Tag characters decode to the ASCII string: "${analysis.hidden_tag_message}". ` +
        `If this string contains instructions or a URL, the description is ` +
        `a steganographic prompt-injection payload.`,
    });
  } else {
    steps.push({
      step_type: "compare-baseline",
      instruction:
        `Remove every invisible codepoint from the description and diff the ` +
        `cleaned text against the original. Inspect whether the cleaned text ` +
        `reveals different word boundaries, different keyword spellings, or ` +
        `different line breaks.`,
      target: `tool:${toolName}:description`,
      expected_observation:
        `Cleaned description differs from the original — the invisible chars ` +
        `were affecting tokenisation or word-spelling as seen by the LLM.`,
    });
  }

  return steps;
}

export function parameterVerificationSteps(
  toolName: string,
  paramName: string,
  analysis: A7FieldAnalysis,
): VerificationStep[] {
  return [
    {
      step_type: "inspect-description",
      instruction:
        `Hex-dump the parameter description and locate invisible codepoints. ` +
        `Parameter descriptions are a secondary injection surface: the LLM ` +
        `reads them when deciding how to populate an argument, so invisible ` +
        `directives here can steer the AI toward dangerous parameter values.`,
      target: `tool:${toolName}:parameter:${paramName}:description`,
      expected_observation:
        `${analysis.hits.length} invisible codepoint(s) observed. Classes: ${classSummary(analysis)}.`,
    },
  ];
}
