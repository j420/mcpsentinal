/**
 * A9 — Encoded or Obfuscated Instructions in Tool Description (Rule Standard v2).
 *
 * REPLACES `packages/analyzer/src/rules/implementations/a9-encoded-instructions.ts`.
 *
 * Detection technique: `composite` (entropy + structural scanning).
 *
 * Threat model:
 *   MCP01 — Prompt injection via descriptions.
 *   AML.T0054 / AML.T0054.002 — LLM direct prompt injection.
 *
 *   An attacker encodes an instruction payload (base64, URL-encoding, hex/unicode
 *   escapes, HTML entities) inside tool / parameter / initialize metadata. Human
 *   reviewers see opaque character runs; the LLM decodes and may follow them.
 *
 * Surfaces scanned (per AnalysisContext):
 *   • tool.description                      (primary — most common surface)
 *   • tool.name                             (secondary — rare but seen)
 *   • input_schema.properties[*].description (B5 overlap, A9 still valid)
 *   • initialize_metadata.server_instructions (H2 overlap, A9 still valid)
 *   • initialize_metadata.server_version
 *
 * Pipeline:
 *   1. gather()  — character-level scanner emits EncodedSite[] per surface
 *   2. judge()   — per-site confidence factors, severity, mixed-encoding merge
 *   3. build()   — render EvidenceChain with source → propagation → sink →
 *                  mitigation → impact → verification-steps
 *
 * Confidence is capped at 0.90: static entropy analysis can false-positive on
 * legitimate compressed/encoded binary data embedded in RFC-style descriptions.
 *
 * Detection coverage contract (explicit, for audit):
 *   Detects   : base64 (incl. base64url), URL-encoded %XX, \xNN hex, \uNNNN
 *               unicode, numeric HTML entities, and mixed combinations of those.
 *   Misses    : base32 / base85 / ascii85 (future work), custom base-N schemes,
 *               XOR/steganographic payloads (handled by entropy sliding-window
 *               analysis in companion detectors), non-English natural language
 *               that legitimately contains \uNNNN escape syntax.
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import {
  gather,
  locationTag,
  toStructuredLocation,
  type EncodedCategory,
  type EncodedSite,
} from "./gather.js";
import { buildVerificationSteps } from "./verification.js";

const RULE_ID = "A9";
const RULE_NAME = "Encoded or Obfuscated Instructions in Tool Description";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054";

const REMEDIATION =
  "Tool descriptions, tool names, parameter descriptions, and the MCP initialize " +
  "`instructions` field must be plain human-readable text. Remove any encoded runs " +
  "(base64, URL-encoding, \\xNN/\\uNNNN escapes, HTML entities). If a description " +
  "legitimately needs to reference a literal encoded value (e.g. RFC example), " +
  "keep it under the per-scheme threshold and surround it with explicit narrative " +
  "context (\"example base64 payload:\"). Review against OWASP MCP01, MITRE " +
  "AML.T0054, and the MCP tool-description publication guidelines.";

/** Confidence cap — entropy/structural analysis can misfire on legitimate binary refs */
const MAX_CONFIDENCE = 0.9;

/** Per-category base severity (mixed-encoding escalates during judge step) */
const BASE_SEVERITY: Record<EncodedCategory, Severity> = {
  "base64-block": "high",
  "url-encoded-block": "high",
  "hex-escape-block": "high",
  "html-entity-block": "medium",
};

// ─── Rule ────────────────────────────────────────────────────────────────────

class A9EncodedInstructionsRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "composite"; // entropy + structural

  analyze(context: AnalysisContext): RuleResult[] {
    const { sites, mixed_locations } = gather(context);
    if (sites.length === 0) return [];

    const out: RuleResult[] = [];

    // Group sites by location-tag so we can emit ONE finding per surface,
    // escalated to critical when ≥2 encoding categories co-locate.
    const byTag = new Map<string, EncodedSite[]>();
    for (const s of sites) {
      const tag = locationTag(s.location);
      const arr = byTag.get(tag) ?? [];
      arr.push(s);
      byTag.set(tag, arr);
    }

    for (const [tag, group] of byTag.entries()) {
      const isMixed = mixed_locations.has(tag);
      out.push(this.buildFinding(group, isMixed));
    }

    return out;
  }

  private buildFinding(group: EncodedSite[], isMixed: boolean): RuleResult {
    // Anchor on the strongest signal (preference: has llm_token → has keywords → longest)
    const primary = pickPrimary(group);
    const categories = Array.from(new Set(group.map((s) => s.category)));
    const severity: Severity = isMixed ? "critical" : BASE_SEVERITY[primary.category];

    const builder = new EvidenceChainBuilder();

    const tag = locationTag(primary.location);
    const primaryLoc = toStructuredLocation(primary.location);
    const preview = primary.raw.slice(0, 120);

    // ── source: where the encoded run lives ──────────────────────────────────
    builder.source({
      source_type:
        primary.location.kind === "server-instructions" ||
        primary.location.kind === "server-version"
          ? "initialize-field"
          : "external-content",
      location: primaryLoc,
      observed: preview,
      rationale:
        `A ${primary.length}-char ${primary.category} run is present inside ${tag} ` +
        `at offset ${primary.offset} (length ${primary.length}). ` +
        `Human reviewers see an opaque character string; the LLM receives the same ` +
        `bytes verbatim and can decode them using built-in capabilities. ` +
        `The field is published by the server operator and is read by the AI client ` +
        `as trusted metadata for tool selection and invocation.` +
        (isMixed
          ? ` This surface also carries other encoding categories (${categories.join(", ")}) — ` +
            `the co-occurrence is a deliberate obfuscation-layering signal.`
          : ""),
    });

    // ── propagation: description flows into AI context ───────────────────────
    builder.propagation({
      propagation_type: "description-directive",
      location: primaryLoc,
      observed:
        `${primary.category} payload is embedded in metadata the MCP client sends to ` +
        `the model as part of the tool-catalog system context. No sanitization layer ` +
        `strips encoded content before model ingestion.`,
    });

    // ── sink: model decodes and may follow instructions ──────────────────────
    builder.sink({
      sink_type: "code-evaluation",
      location: primaryLoc,
      observed:
        primary.decoded !== null
          ? `Decoded payload preview: "${flattenWhitespace(primary.decoded.slice(0, 140))}"` +
            (primary.llm_token_hit
              ? ` — contains LLM control token "${primary.llm_token_hit}".`
              : primary.keyword_hits > 0
                ? ` — contains ${primary.keyword_hits} injection-keyword hit(s).`
                : ".")
          : `Encoded run did not decode cleanly, but its shape (length ${primary.length}, ` +
            `entropy ${primary.entropy.toFixed(2)} bits/char) is inconsistent with legitimate ` +
            `description text.`,
      cve_precedent: undefined,
    });

    // ── mitigation: no description sanitizer ─────────────────────────────────
    builder.mitigation({
      mitigation_type: "sanitizer-function",
      present: false,
      location: primaryLoc,
      detail:
        "No entropy or encoding filter is applied to tool descriptions or initialize " +
        "instructions before they enter the model context window at the MCP client boundary.",
    });

    // ── impact: cross-agent propagation via injected directives ──────────────
    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: primary.llm_token_hit || primary.keyword_hits > 0 ? "trivial" : "moderate",
      scenario:
        "A server publisher hides prompt-injection instructions inside encoded runs " +
        "in tool metadata or initialize fields. Human code review (GitHub PR view, npm " +
        "package page) shows the encoded form and is unlikely to decode it. The MCP " +
        "client delivers the same bytes to the LLM, which can silently decode and " +
        "follow the hidden directive on every tool-selection pass.",
    });

    // ── confidence factors ───────────────────────────────────────────────────
    // Structural match gets a solid positive anchor.
    builder.factor(
      "structural_encoding_run",
      0.08,
      `Deterministic scanner matched ${primary.category} at ${tag}@${primary.offset}+${primary.length}`,
    );

    // Entropy factor — base64 runs at 5.7+ bits/char are essentially never legitimate English.
    if (primary.entropy >= 5.5) {
      builder.factor(
        "high_entropy",
        0.05,
        `Shannon entropy ${primary.entropy.toFixed(2)} bits/char exceeds natural-language ceiling (~4.5).`,
      );
    } else if (primary.entropy < 4.0) {
      builder.factor(
        "low_entropy_encoded_shape",
        -0.02,
        `Entropy ${primary.entropy.toFixed(2)} bits/char is low — the structural match may be coincidental.`,
      );
    }

    // Decoded-payload signals.
    if (primary.llm_token_hit) {
      builder.factor(
        "llm_control_token_after_decode",
        0.18,
        `Decoded payload contains LLM control token "${primary.llm_token_hit}" — a deterministic ` +
          `indicator that the encoding was deliberately hiding an instruction, not data.`,
      );
    }
    if (primary.keyword_hits >= 2) {
      builder.factor(
        "multiple_injection_keywords_after_decode",
        0.1,
        `Decoded payload contains ${primary.keyword_hits} injection-keyword hits.`,
      );
    } else if (primary.keyword_hits === 1) {
      builder.factor(
        "single_injection_keyword_after_decode",
        0.05,
        `Decoded payload contains one injection-keyword hit.`,
      );
    }

    // Deliberate obfuscation layering.
    if (isMixed) {
      builder.factor(
        "mixed_encoding_layering",
        0.12,
        `Multiple encoding categories co-occur in ${tag}: ${categories.join(", ")}. ` +
          `Layering is a deliberate obfuscation strategy, not an accident of content.`,
      );
    }

    // Non-Latin surrounding context — downgrade.
    if (primary.surrounding_latin_ratio < 0.5) {
      builder.factor(
        "non_latin_surrounding_context",
        -0.08,
        `Surrounding text has ${Math.round(primary.surrounding_latin_ratio * 100)}% Latin-script characters. ` +
          `Encoded-looking runs in non-Latin descriptions are more likely to be literal data or ` +
          `transliteration artifacts.`,
      );
    }

    // Encoded run that refused to decode cleanly — mild downgrade.
    if (primary.decoded === null && primary.category !== "html-entity-block") {
      builder.factor(
        "decoder_failed",
        -0.05,
        `Structural shape matched ${primary.category} but the canonical decoder did not produce ` +
          `printable output — may be double-encoded or a custom alphabet.`,
      );
    }

    // ── reference ─────────────────────────────────────────────────────────────
    builder.reference({
      id: MITRE,
      title: "MITRE ATLAS — AML.T0054 LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        "Encoded instructions in tool descriptions are a documented LLM prompt-injection " +
        "technique (direct variant AML.T0054.002). The attacker's goal is to bypass human " +
        "review while keeping the payload machine-decodable.",
    });

    // ── verification steps ────────────────────────────────────────────────────
    for (const step of buildVerificationSteps(primary)) {
      builder.verification(step);
    }

    const chain = builder.build();

    // Apply the 0.90 confidence cap explicitly (builder clamps at 0.99).
    if (chain.confidence > MAX_CONFIDENCE) {
      chain.confidence = MAX_CONFIDENCE;
      chain.confidence_factors.push({
        factor: "entropy_static_analysis_cap",
        adjustment: 0,
        rationale:
          "A9 static entropy analysis can false-positive on legitimate compressed/encoded " +
          "binary data in descriptions; confidence capped at 0.90 to preserve reviewer headroom.",
      });
    }

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Replace newline / carriage-return / tab characters with a single space via
 * character-level scanner (no regex literals per v2 contract).
 */
function flattenWhitespace(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const cp = s.charCodeAt(i);
    if (cp === 0x0a || cp === 0x0d || cp === 0x09) out += " ";
    else out += s[i];
  }
  return out;
}

function pickPrimary(group: EncodedSite[]): EncodedSite {
  // Prefer sites with an LLM control token hit, then with keyword hits, then longest
  let best: EncodedSite = group[0];
  for (const s of group) {
    if (scoreSite(s) > scoreSite(best)) best = s;
  }
  return best;
}

function scoreSite(s: EncodedSite): number {
  let x = s.length;
  if (s.llm_token_hit) x += 10_000;
  if (s.keyword_hits > 0) x += 1_000 * s.keyword_hits;
  if (s.decoded !== null) x += 100;
  return x;
}

// ─── Register ────────────────────────────────────────────────────────────────

registerTypedRuleV2(new A9EncodedInstructionsRule());
