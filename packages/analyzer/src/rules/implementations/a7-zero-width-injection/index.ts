/**
 * A7 — Zero-Width / Invisible Character Injection (Rule Standard v2)
 *
 * REPLACES the legacy flat TypedRule at
 * `packages/analyzer/src/rules/implementations/a6-unicode-homoglyph.ts`
 * (A7 shared a file with A6 in v1). Detection semantics are preserved.
 *
 * Detection technique: "unicode" — pure codepoint-range arithmetic against a
 * catalogue of 15 invisible / zero-width / bidi / tag / variation-selector /
 * width-space ranges. No regex literals.
 *
 * Surfaces scanned:
 *   - Tool NAME (critical — the identity surface used for routing)
 *   - Tool DESCRIPTION (critical if tag-decoded hidden message is present)
 *   - Tool parameter DESCRIPTIONS (B5 overlap, secondary injection surface)
 *
 * Edge-case policy:
 *   - ZWJ / ZWNJ flanked on both sides by emoji codepoints is legitimate
 *     and not reported.
 *   - Variation selectors immediately after an emoji codepoint in a
 *     DESCRIPTION are legitimate presentation selectors and not reported.
 *   - BOM at position 0 of a field is legitimate; BOM elsewhere is reported.
 *   - In tool NAMES, variation selectors and BOMs are always reported
 *     (identifiers do not carry them).
 *
 * Confidence cap: 0.95. Codepoint detection is exact; the 0.05 reserved head
 * room reflects the residual intent ambiguity on single-codepoint cases
 * (e.g. a stray soft hyphen in a one-off description).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import { gather, type A7FieldAnalysis, type A7ToolGather, type A7ParamAnalysis } from "./gather.js";
import {
  nameFieldVerificationSteps,
  descriptionFieldVerificationSteps,
  parameterVerificationSteps,
} from "./verification.js";

const RULE_ID = "A7";
const RULE_NAME = "Zero-Width and Invisible Character Injection";
const OWASP = "MCP01-prompt-injection" as const;
const MITRE = "AML.T0054";
const REMEDIATION =
  "Strip every invisible Unicode codepoint from tool names, descriptions, and parameter descriptions " +
  "before storing or serving them. Reject tool names containing any of: U+200B–U+200D, U+2060, U+FEFF " +
  "(zero-width / BOM); U+00AD (soft hyphen); U+202A–U+202E, U+2066–U+2069 (bidi controls); " +
  "U+E0000–U+E007F (tag characters); U+FE00–U+FE0F (variation selectors). For descriptions, permit " +
  "variation selectors only when the preceding codepoint is an emoji, and permit ZWJ only between " +
  "emoji codepoints. Tag characters must NEVER appear in server-side content — decoded they form " +
  "ASCII messages invisible to human reviewers.";

const CONFIDENCE_CAP = 0.95;

function capConfidence(n: number): number {
  return Math.min(CONFIDENCE_CAP, Math.max(0.05, n));
}

class ZeroWidthInjectionRuleV2 implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "unicode";

  analyze(context: AnalysisContext): RuleResult[] {
    const findings: RuleResult[] = [];
    const g = gather(context);

    for (const t of g.tools) {
      this.maybeEmitNameFinding(t, findings);
      this.maybeEmitDescriptionFinding(t, findings);
      this.maybeEmitBidiFinding(t, findings);
      for (const p of t.parameter_analyses) {
        this.maybeEmitParameterFinding(t, p, findings);
      }
    }

    return findings;
  }

  // ───────────── tool name finding ─────────────

  private maybeEmitNameFinding(t: A7ToolGather, out: RuleResult[]): void {
    const a = t.name_analysis;
    if (a.hits.length === 0) return;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool:${t.tool_name}:name`,
      observed: a.hits
        .slice(0, 5)
        .map((h) => `${h.label} (${h.range_name}) at index ${h.position}`)
        .join(", "),
      rationale:
        `Tool name contains ${a.hits.length} invisible codepoint(s). An identifier is a public ` +
        `string used by AI clients to route invocations — any invisible codepoint in an identifier ` +
        `allows two distinct strings to appear identical to humans while being unequal to machines.`,
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: `tool:${t.tool_name}:registration`,
      observed:
        `AI client receives the tool name verbatim during tools/list. Invisible codepoints ` +
        `are transmitted as UTF-8 bytes and retained in every downstream lookup and display, ` +
        `enabling shadow-tool routing.`,
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: `ai-client:tool-invocation`,
      observed:
        `Two tool names identical to the human eye but differing by an invisible codepoint ` +
        `cause non-deterministic routing — any invocation intended for the legitimate tool may ` +
        `be satisfied by the attacker's tool.`,
    });

    builder.mitigation({
      mitigation_type: "input-validation",
      present: false,
      location: `tool:${t.tool_name}:registration`,
      detail: `No invisible-codepoint stripping or rejection is applied at MCP tool registration.`,
    });

    builder.impact({
      impact_type: "credential-theft",
      scope: "ai-client",
      exploitability: "trivial",
      scenario:
        `A shadow tool whose name differs from a legitimate tool by a single invisible ZWSP ` +
        `intercepts invocations that the user intended for the legitimate tool, silently capturing ` +
        `the user's parameters.`,
    });

    builder.factor(
      "invisible_in_identifier",
      0.22,
      `${a.hits.length} invisible codepoint(s) in a tool name — identifiers must not carry invisible characters`,
    );

    if (a.hits.some((h) => h.class === "bidi-override")) {
      builder.factor(
        "bidi_in_identifier",
        0.18,
        `Tool name contains bidirectional-override codepoints — reviewers see a different string than the LLM reads`,
      );
    }

    builder.reference({
      id: "AML.T0054",
      title: "MITRE ATLAS — LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        `Invisible-codepoint insertion in tool identifiers is an established variant of prompt ` +
        `injection: the invisible codepoints smuggle information past the human-review surface.`,
    });

    for (const s of nameFieldVerificationSteps(t.tool_name, a)) builder.verification(s);

    const chain = builder.build();
    chain.confidence = capConfidence(chain.confidence);

    out.push({
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    });
  }

  // ───────────── description finding ─────────────

  private maybeEmitDescriptionFinding(t: A7ToolGather, out: RuleResult[]): void {
    const a = t.description_analysis;
    if (!a || a.hits.length === 0) return;
    // Bidi gets its own dedicated finding (below); do not duplicate.
    if (a.classes_seen.length === 1 && a.classes_seen[0] === "bidi-override") return;

    const hasTagMessage = a.hidden_tag_message !== null;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool:${t.tool_name}:description`,
      observed: a.hits
        .slice(0, 5)
        .map((h) => `${h.label} (${h.range_name}) at index ${h.position}`)
        .join(", "),
      rationale:
        `Tool description contains ${a.hits.length} invisible codepoint(s) spanning ` +
        `${a.classes_seen.length} class(es): ${a.classes_seen.join(", ")}. ` +
        (hasTagMessage
          ? `Tag codepoints decode to a hidden ASCII message: "${a.hidden_tag_message}".`
          : `No hidden ASCII message was decoded, but the invisible codepoints still smuggle content past the human reviewer.`),
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: `ai-client:context-window`,
      observed:
        `Tool description is included verbatim in the AI client's tool-selection context. ` +
        `Invisible codepoints are preserved byte-for-byte and consumed by the LLM as part of the text.`,
    });

    builder.sink({
      sink_type: "code-evaluation",
      location: `ai-client:instruction-processing`,
      observed: hasTagMessage
        ? `Hidden instructions decoded from tag characters: "${a.hidden_tag_message}" — the LLM processes these as text in its context window.`
        : `Invisible codepoints may encode directives (via tokenisation artefacts, bidi reordering, or width-space substitution) that the LLM processes but human reviewers cannot see.`,
    });

    builder.mitigation({
      mitigation_type: "input-validation",
      present: false,
      location: `tool:${t.tool_name}:description`,
      detail: `No invisible-codepoint stripping is applied to descriptions before AI processing.`,
    });

    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: hasTagMessage ? "trivial" : "moderate",
      scenario: hasTagMessage
        ? `The description carries a hidden ASCII instruction decoded from tag characters. Human reviewers see clean text; the LLM processes the hidden payload verbatim.`
        : `Invisible codepoints alter the LLM's tokenisation or word boundaries, letting the attacker control how the description is read while preserving a benign appearance to a human reviewer.`,
    });

    builder.factor(
      "invisible_chars_in_description",
      Math.min(0.05 + a.hits.length * 0.02, 0.18),
      `${a.hits.length} invisible codepoint(s) in the description`,
    );

    if (hasTagMessage) {
      builder.factor(
        "hidden_tag_message_decoded",
        0.25,
        `Tag characters decode to the ASCII string "${a.hidden_tag_message}" — a steganographic payload`,
      );
    }

    if (a.classes_seen.length >= 2) {
      builder.factor(
        "multi_class_invisibles",
        0.08,
        `Invisibles drawn from ${a.classes_seen.length} distinct classes (${a.classes_seen.join(", ")}) — coordinated obfuscation`,
      );
    }

    builder.reference({
      id: "AML.T0054",
      title: "MITRE ATLAS — LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        `Invisible codepoints in tool metadata are a documented vector for steganographic prompt injection.`,
    });

    for (const s of descriptionFieldVerificationSteps(t.tool_name, a)) builder.verification(s);

    const chain = builder.build();
    chain.confidence = capConfidence(chain.confidence);

    out.push({
      rule_id: RULE_ID,
      severity: hasTagMessage ? "critical" : "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    });
  }

  // ───────────── bidi-only finding (specialised) ─────────────

  private maybeEmitBidiFinding(t: A7ToolGather, out: RuleResult[]): void {
    const a = t.description_analysis;
    if (!a) return;
    const bidiHits = a.hits.filter((h) => h.class === "bidi-override");
    if (bidiHits.length === 0) return;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool:${t.tool_name}:description`,
      observed: bidiHits.map((h) => `${h.label} at index ${h.position}`).join(", "),
      rationale:
        `Tool description contains ${bidiHits.length} bidirectional-control codepoint(s). ` +
        `U+202E (RIGHT-TO-LEFT OVERRIDE) and friends reorder rendered text independently of ` +
        `logical order — the text a human reads is the REVERSE of what the LLM processes.`,
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: `ai-client:context-window`,
      observed:
        `Bidi overrides cause divergence between rendered and logical text. Human reviewers ` +
        `see "deetsurT" while the LLM reads "Trusted" (or vice versa).`,
    });

    builder.sink({
      sink_type: "code-evaluation",
      location: `ai-client:instruction-processing`,
      observed:
        `LLM consumes the description in logical order and executes embedded instructions — ` +
        `the Trojan Source style (CVE-2021-42574) attack against the AI review loop.`,
    });

    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: "trivial",
      scenario:
        `A tool description that renders as benign text to a human reviewer reads as an attacker-controlled directive to the LLM.`,
    });

    builder.factor(
      "bidi_override_in_description",
      0.22,
      `${bidiHits.length} bidirectional-control codepoint(s)`,
    );

    builder.reference({
      id: "CVE-2021-42574",
      title: "Trojan Source — Invisible Vulnerabilities via Bidirectional Unicode",
      url: "https://trojansource.codes/",
      relevance:
        `Bidirectional-override codepoints were originally documented as an attack vector against source-code review; the same divergence between rendered and logical text attacks MCP tool descriptions.`,
    });

    builder.verification({
      step_type: "inspect-description",
      instruction:
        `Render the description in a bidi-naive environment (e.g. a raw hex dump) and compare to ` +
        `the rendering in a terminal or browser. If the two representations differ, the description ` +
        `is using bidi overrides to deceive reviewers.`,
      target: `tool:${t.tool_name}:description`,
      expected_observation:
        `Logical-order byte sequence differs from the rendered order at bidi-override boundaries.`,
    });

    const chain = builder.build();
    chain.confidence = capConfidence(chain.confidence);

    out.push({
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    });
  }

  // ───────────── parameter finding ─────────────

  private maybeEmitParameterFinding(t: A7ToolGather, p: A7ParamAnalysis, out: RuleResult[]): void {
    if (p.hits.length === 0) return;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "user-parameter",
      location: `tool:${t.tool_name}:parameter:${p.parameter_name}:description`,
      observed: p.hits.slice(0, 3).map((h) => `${h.label} (${h.range_name})`).join(", "),
      rationale:
        `Parameter description contains ${p.hits.length} invisible codepoint(s). Parameter ` +
        `descriptions are consumed by the LLM when populating arguments — an invisible directive ` +
        `here steers the AI toward an attacker-chosen parameter value.`,
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: `tool:${t.tool_name}:parameter:${p.parameter_name}`,
      observed:
        `Invisible codepoints in the parameter description are preserved through tools/list and ` +
        `fed to the LLM during argument filling.`,
    });

    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: "moderate",
      scenario:
        `The hidden instruction in the parameter description manipulates how the LLM fills the argument, e.g. directing it to emit a specific path or token value.`,
    });

    builder.factor(
      "invisible_in_parameter",
      0.12,
      `${p.hits.length} invisible codepoint(s) in parameter description — secondary injection surface`,
    );

    builder.reference({
      id: "AML.T0054",
      title: "MITRE ATLAS — LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        `Parameter descriptions are a secondary LLM-reading surface and therefore a secondary prompt-injection surface.`,
    });

    for (const s of parameterVerificationSteps(t.tool_name, p.parameter_name, p)) {
      builder.verification(s);
    }

    const chain = builder.build();
    chain.confidence = capConfidence(chain.confidence);

    out.push({
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    });
  }
}

registerTypedRuleV2(new ZeroWidthInjectionRuleV2());
