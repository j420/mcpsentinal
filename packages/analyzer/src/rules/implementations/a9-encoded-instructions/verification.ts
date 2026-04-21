/**
 * A9 verification step builders.
 *
 * Every step carries a concrete `target` location so an auditor can re-extract
 * the same bytes from the same field the rule inspected. The `expected_observation`
 * lets them confirm without running our scanner.
 *
 * Four step builders:
 *   1. inspect-description — pinpoint the encoded block inside the field
 *   2. test-input          — provide the decoder invocation
 *   3. inspect-description — check the decoded payload for directives
 *   4. inspect-description — compare against benign-context heuristic
 */

import type { VerificationStep } from "../../../evidence.js";
import type { EncodedCategory, EncodedSite } from "./gather.js";
import { locationTag } from "./gather.js";

function decoderHint(category: EncodedCategory): string {
  switch (category) {
    case "base64-block":
      return "`echo -n '<block>' | base64 -d`  (or base64url-aware variant for - and _ chars)";
    case "url-encoded-block":
      return "`python3 -c 'import urllib.parse,sys;print(urllib.parse.unquote(sys.argv[1]))' '<block>'`";
    case "hex-escape-block":
      return "`python3 -c 'import codecs,sys;print(codecs.decode(sys.argv[1].replace(chr(92)+\"x\",\"\"),\"hex\").decode())' '<block>'`";
    case "html-entity-block":
      return "`python3 -c 'import html,sys;print(html.unescape(sys.argv[1]))' '<block>'`";
  }
}

/**
 * Build the four verification steps for an A9 finding.
 * Every target is a Location tag usable by a human reviewer.
 */
export function buildVerificationSteps(site: EncodedSite): VerificationStep[] {
  const tag = locationTag(site.location);
  // Turn "base64-block" → "base64 block" via character scan (no regex).
  let categoryLabel = "";
  for (let i = 0; i < site.category.length; i++) {
    categoryLabel += site.category.charCodeAt(i) === 0x2d ? " " : site.category[i];
  }
  const decoderText = decoderHint(site.category);
  const preview = site.raw.slice(0, 80) + (site.raw.length > 80 ? "..." : "");

  const steps: VerificationStep[] = [];

  // Step 1 — locate the block
  steps.push({
    step_type: "inspect-description",
    instruction:
      `Locate the ${categoryLabel} at offset ${site.offset} (${site.length} chars) ` +
      `in ${tag}. Verify its presence verbatim before re-running any decoder.`,
    target: `${tag}@${site.offset}+${site.length}`,
    expected_observation:
      `A contiguous ${site.length}-character run starting "${preview}" matching the ` +
      `${categoryLabel} alphabet.`,
  });

  // Step 2 — decoder invocation
  steps.push({
    step_type: "test-input",
    instruction:
      `Decode the block using the canonical decoder for this scheme. ` +
      `Example: ${decoderText}. Do NOT execute the decoded payload — only inspect it.`,
    target: `${tag}@${site.offset}+${site.length}`,
    expected_observation:
      site.decoded !== null
        ? `Decoder produces readable text; preview: "${site.decoded.slice(0, 120)}".`
        : `Decoder produces non-printable bytes — the block may be double-encoded ` +
          `or use a non-standard alphabet; treat as suspicious regardless.`,
  });

  // Step 3 — scan decoded payload for injection markers
  steps.push({
    step_type: "inspect-description",
    instruction:
      `Read the decoded payload and look for LLM-manipulation language: ` +
      `"ignore previous instructions", role prefixes (system:, assistant:, <|im_start|>), ` +
      `exfiltration targets (.ssh/id_rsa, webhook URLs), or capability directives ` +
      `(execute, reveal, eval). The goal is to confirm the encoded content is an ` +
      `instruction payload, not legitimate binary data.`,
    target: `${tag}:decoded-payload`,
    expected_observation:
      site.llm_token_hit !== null
        ? `Decoded payload contains LLM control token "${site.llm_token_hit}" — ` +
          `proof of injection intent.`
        : site.keyword_hits > 0
          ? `Decoded payload contains ${site.keyword_hits} injection-keyword hit(s) ` +
            `(ignore/override/system/prompt/credential/etc.).`
          : `Decoded payload has no overt injection keywords; assess whether the encoding ` +
            `is justified by surrounding natural-language context.`,
  });

  // Step 4 — benign-context heuristic
  steps.push({
    step_type: "inspect-description",
    instruction:
      `Read the ±100-character window around offset ${site.offset}. If the surrounding ` +
      `text describes the block as literal data (e.g. "example payload:", "base64 of the ` +
      `response:", "RFC illustrative value"), downgrade the finding to informational. ` +
      `Otherwise treat the encoded run as a human-review-evading injection attempt.`,
    target: `${tag}@${Math.max(0, site.offset - 100)}+${site.length + 200}`,
    expected_observation:
      `A ${Math.round(site.surrounding_latin_ratio * 100)}% Latin-script context with ` +
      `no natural-language justification for the encoded block — the reviewer should ` +
      `find no "this is example base64" disclaimer.`,
  });

  return steps;
}
