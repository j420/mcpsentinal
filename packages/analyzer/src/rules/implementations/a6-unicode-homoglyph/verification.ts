/**
 * A6 — Verification steps.
 *
 * Every finding emits reviewer-actionable steps that point at a specific
 * Location (tool name, tool description, or tool-pair) so an auditor can
 * independently reproduce the observation.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { FieldAnalysis, HomoglyphHit } from "./gather.js";

function toolLoc(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
const TOOL_CAPABILITY_LOC: Location = { kind: "capability", capability: "tools" };

function summariseHits(hits: HomoglyphHit[]): string {
  return hits
    .map((h) => `${h.label} "${String.fromCodePoint(h.codepoint)}" (impersonates "${h.latin_letter}", script=${h.script})`)
    .join("; ");
}

/** Verification steps for a homoglyph finding in a tool NAME */
export function toolNameVerificationSteps(
  toolName: string,
  analysis: FieldAnalysis,
  normalisedForm: string,
): VerificationStep[] {
  const hits = analysis.hits;
  const scripts = analysis.lookalike_scripts.join(", ");

  const steps: VerificationStep[] = [
    {
      step_type: "inspect-description",
      instruction:
        `Hex-dump the tool name and inspect each codepoint against the Unicode ` +
        `Character Database. Compare suspicious codepoints against Unicode TR39 ` +
        `(confusables.txt). Example: Latin "a" is U+0061 while Cyrillic "а" is ` +
        `U+0430 — they are visually identical but different characters.`,
      target: toolLoc(toolName),
      expected_observation:
        `${hits.length} confusable codepoint(s) present in the name of tool "${toolName}". ` +
        `Scripts observed: ${scripts}. Hits: ${summariseHits(hits)}.`,
    },
    {
      step_type: "compare-baseline",
      instruction:
        `Apply Unicode TR39 confusable normalisation to the name of tool "${toolName}" ` +
        `(normalised form: "${normalisedForm}") and compare against every other tool ` +
        `name in this server and known legitimate tool names in the same ecosystem ` +
        `(e.g. Anthropic reference servers). Any collision confirms visual ` +
        `impersonation of an existing tool identity.`,
      target: toolLoc(toolName),
      expected_observation:
        normalisedForm !== toolName
          ? `Normalised form "${normalisedForm}" differs from the raw tool ` +
            `name and may match an existing legitimate tool — confirming visual impersonation.`
          : `Normalisation produces the same string, but the identifier still ` +
            `mixes Latin and non-Latin scripts, which is still suspicious.`,
    },
  ];

  return steps;
}

/** Verification steps for a homoglyph cluster in a tool DESCRIPTION */
export function descriptionVerificationSteps(
  toolName: string,
  analysis: FieldAnalysis,
): VerificationStep[] {
  return [
    {
      step_type: "inspect-description",
      instruction:
        `Hex-dump the tool description and list every codepoint with its ` +
        `Unicode script. Count non-Latin codepoints that are confusables for ` +
        `Latin letters — those are the candidates for steganographic prompt ` +
        `payloads embedded in apparently-English prose.`,
      target: toolLoc(toolName),
      expected_observation:
        `${analysis.hits.length} homoglyph codepoint(s) distributed across ` +
        `${analysis.lookalike_scripts.length} script block(s): ` +
        `${analysis.lookalike_scripts.join(", ")} — inside the description of tool "${toolName}".`,
    },
    {
      step_type: "compare-baseline",
      instruction:
        `Normalise the description of tool "${toolName}" using TR39 confusables and diff ` +
        `against the original. If the normalised text contains different words than the ` +
        `original, the description is using confusables to bypass keyword-based ` +
        `prompt-injection filters while remaining fully legible to an LLM.`,
      target: toolLoc(toolName),
      expected_observation:
        `Normalised description reveals words/phrases that were obscured by ` +
        `confusable substitution — confirming obfuscation intent.`,
    },
  ];
}

/** Verification steps for a shadow-tool collision */
export function shadowCollisionVerificationSteps(
  leftToolName: string,
  rightToolName: string,
  normalisedForm: string,
): VerificationStep[] {
  return [
    {
      step_type: "inspect-description",
      instruction:
        `Print the codepoint sequences of both tool names side by side. ` +
        `Find the differing indices — each difference is where one name uses a ` +
        `non-Latin lookalike in place of a Latin letter.`,
      target: toolLoc(leftToolName),
      expected_observation:
        `At least one index where the codepoints of "${leftToolName}" and "${rightToolName}" ` +
        `differ but the rendered glyphs are visually identical.`,
    },
    {
      step_type: "compare-baseline",
      instruction:
        `Confirm that both tool names "${leftToolName}" and "${rightToolName}" normalise to ` +
        `the same Latin string "${normalisedForm}". The AI client cannot distinguish these ` +
        `tools from one another — invocation routing is a coin-flip controlled by the attacker.`,
      target: TOOL_CAPABILITY_LOC,
      expected_observation:
        `Both tool names collapse to the identical normalised form — any ` +
        `AI client that routes by raw-identifier equality but displays to a ` +
        `human with Unicode-aware rendering is vulnerable.`,
    },
  ];
}
