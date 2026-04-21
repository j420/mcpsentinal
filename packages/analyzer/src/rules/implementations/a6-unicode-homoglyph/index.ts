/**
 * A6 — Unicode Homoglyph Attack (Rule Standard v2)
 *
 * REPLACES the legacy flat TypedRule at
 * `packages/analyzer/src/rules/implementations/a6-unicode-homoglyph.ts`.
 *
 * Detection technique: "unicode" — pure codepoint-range arithmetic with
 * script-block classification and TR39 confusable tables. No regex, no
 * string-matching against mutable vocabularies.
 *
 * Attack surfaces preserved from the legacy implementation:
 *   - Tool name containing Cyrillic/Greek/Armenian/Cherokee lookalikes for
 *     Latin letters ("reаd_file" with Cyrillic "а" instead of Latin "a").
 *   - Tool description containing ≥3 homoglyph clusters — indicates
 *     steganographic obfuscation of prompt-injection payloads.
 *   - Shadow-tool collision: two tools in the same server whose names
 *     normalise to the same Latin string — the AI client cannot route
 *     deterministically.
 *   - Fullwidth Latin (U+FF21–U+FF5E) and Mathematical Alphanumerics
 *     (U+1D400–U+1D7FF) as whole-script confusable families.
 *
 * Confidence cap: 0.95. Codepoint detection is deterministic but the INTENT
 * (is this a homoglyph attack vs a legitimate internationalised identifier?)
 * is inferred from script-mixing policy, which can be wrong in rare edge
 * cases (e.g. a multilingual corpus legitimately mixing Latin and Greek in
 * prose). See CHARTER.md → lethal_edge_cases.
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
import type { Location } from "../../location.js";
import { gather, normaliseConfusables, type A6ToolGather, type FieldAnalysis } from "./gather.js";
import {
  toolNameVerificationSteps,
  descriptionVerificationSteps,
  shadowCollisionVerificationSteps,
} from "./verification.js";

/**
 * Structured Location builders (Rule Standard v2 §2). Every link cites a
 * v2 `Location`; the "name vs description vs registration vs invocation"
 * distinction is preserved in the link's `observed`/`rationale` narrative
 * rather than encoded in a prose string.
 */
function toolLoc(tool_name: string): Location {
  return { kind: "tool", tool_name };
}
const TOOL_CAPABILITY_LOC: Location = { kind: "capability", capability: "tools" };

const RULE_ID = "A6";
const RULE_NAME = "Unicode Homoglyph Attack";
const OWASP = "MCP02-tool-poisoning" as const;
const MITRE = "AML.T0054";
const REMEDIATION =
  "Tool names MUST use only ASCII Latin characters (a-z, A-Z, 0-9, underscore). " +
  "Non-Latin codepoints that render identically to Latin letters (Cyrillic 'а'=U+0430 vs Latin 'a'=U+0061, " +
  "Greek 'Ο'=U+039F vs Latin 'O'=U+004F) enable tool-identity impersonation. " +
  "Tool descriptions should use a single Unicode script — mixed-script prose should be restricted to " +
  "legitimate internationalisation contexts and reviewed for confusable obfuscation. " +
  "Reject tool registrations whose names mix Latin with lookalike scripts, and normalise descriptions " +
  "through UAX #39 confusable folding before indexing.";

/** Cap for A6 findings — codepoint detection is deterministic, intent is inferred */
const CONFIDENCE_CAP = 0.95;

function capConfidence(n: number): number {
  return Math.min(CONFIDENCE_CAP, Math.max(0.05, n));
}

class UnicodeHomoglyphRuleV2 implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "unicode";

  analyze(context: AnalysisContext): RuleResult[] {
    const findings: RuleResult[] = [];
    const g = gather(context);

    for (const t of g.tools) {
      this.maybeEmitToolNameFinding(t, findings);
      this.maybeEmitDescriptionFinding(t, findings);
    }

    for (const collision of g.shadow_collisions) {
      this.emitShadowCollisionFinding(collision, findings);
    }

    return findings;
  }

  // ───────────────────── tool name finding ─────────────────────

  private maybeEmitToolNameFinding(t: A6ToolGather, out: RuleResult[]): void {
    const a = t.name_analysis;
    // Tool name is Latin-dominant AND has a lookalike confusable? → attack.
    // Single-script identifiers (e.g. a tool name entirely in Greek) are NOT
    // flagged — those are legitimate localisation, not impersonation.
    if (!a.is_mixed_latin_lookalike) return;
    if (a.hits.length === 0) return;

    const normalised = normaliseConfusables(t.tool_name);
    const normalisationChanges = normalised !== t.tool_name;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: toolLoc(t.tool_name),
      observed:
        `tool name "${t.tool_name}" — ` +
        a.hits
          .slice(0, 5)
          .map((h) => `${h.label} impersonating "${h.latin_letter}"`)
          .join(", "),
      rationale:
        `Tool name is Latin-dominant but contains ${a.hits.length} confusable codepoint(s) ` +
        `from lookalike script(s): ${a.lookalike_scripts.join(", ")}. Tool names are registered ` +
        `by external authors and accepted by AI clients as trusted identifiers — a Latin-visual ` +
        `name with hidden non-Latin codepoints cannot be routed deterministically.`,
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: toolLoc(t.tool_name),
      observed:
        `Registration of tool "${t.tool_name}" during tools/list — AI client receives the name ` +
        `and treats it as a unique identifier. No Unicode-script validation is part of the MCP ` +
        `initialize/list handshake — the mixed-script name propagates into tool-selection context ` +
        `untouched.`,
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: toolLoc(t.tool_name),
      observed:
        `Invocation routing for "${t.tool_name}" — the AI client cannot distinguish it from ` +
        `"${normalised}" when selecting a tool by name; invocation is routed to the attacker's ` +
        `tool, which receives the user's parameters and privileges.`,
      cve_precedent: "CWE-1007",
    });

    builder.mitigation({
      mitigation_type: "input-validation",
      present: false,
      location: toolLoc(t.tool_name),
      detail:
        `No Unicode-script validation or TR39 confusable normalisation is applied to tool names ` +
        `during registration or during AI-client routing.`,
    });

    builder.impact({
      impact_type: "credential-theft",
      scope: "ai-client",
      exploitability: "trivial",
      scenario:
        `An attacker registers a tool whose name is visually identical to a trusted tool but ` +
        `uses a Cyrillic/Greek/Cherokee lookalike in at least one position. When the AI selects ` +
        `"the file reader" by name, the attacker-controlled tool is invoked and receives the ` +
        `user's parameters (paths, tokens, file contents) as input.`,
    });

    builder.factor(
      "confusable_codepoints_in_name",
      Math.min(0.15 + a.hits.length * 0.02, 0.22),
      `${a.hits.length} confusable codepoint(s) in tool name — each is an independent substitution`,
    );

    builder.factor(
      normalisationChanges ? "normalisation_reveals_latin_form" : "normalisation_unchanged",
      normalisationChanges ? 0.15 : -0.08,
      normalisationChanges
        ? `Tool name normalises to "${normalised}" which may collide with an existing legitimate tool`
        : `Tool name is unchanged after normalisation — the confusables do not map to a known Latin form`,
    );

    builder.factor(
      "mixed_latin_and_lookalike_script",
      0.12,
      `Single identifier contains both Latin codepoints and codepoints from: ${a.lookalike_scripts.join(", ")}`,
    );

    builder.reference({
      id: "CWE-1007",
      title: "Insufficient Visual Distinction of Homoglyphs Before Rendering",
      url: "https://cwe.mitre.org/data/definitions/1007.html",
      relevance:
        `Tool name exploits Unicode homoglyphs to create visual confusion between distinct ` +
        `identifiers — matches CWE-1007 exactly. Unicode TR39 confusable tables define the ` +
        `equivalence classes used here.`,
    });

    for (const s of toolNameVerificationSteps(t.tool_name, a, normalised)) {
      builder.verification(s);
    }

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

  // ─────────────────── description finding ────────────────────

  private maybeEmitDescriptionFinding(t: A6ToolGather, out: RuleResult[]): void {
    const a: FieldAnalysis | null = t.description_analysis;
    if (!a) return;
    // Descriptions are more permissive — require ≥3 confusable clusters before firing.
    if (a.hits.length < 3) return;
    if (!a.is_mixed_latin_lookalike) return;

    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: toolLoc(t.tool_name),
      observed:
        `tool "${t.tool_name}" description — ` +
        `${a.hits.length} confusable codepoint(s) across ` +
        `${a.lookalike_scripts.length} script block(s): ${a.lookalike_scripts.join(", ")}`,
      rationale:
        `Tool description contains ${a.hits.length} homoglyph characters — well above the rate ` +
        `expected from legitimate multilingual prose. Clustered non-Latin confusables inside ` +
        `otherwise-Latin text is a known obfuscation technique for prompt-injection payloads that ` +
        `evade keyword filters.`,
    });

    builder.propagation({
      propagation_type: "description-directive",
      location: toolLoc(t.tool_name),
      observed:
        `Mixed-script description for "${t.tool_name}" is transmitted verbatim to the LLM as part of the tool-selection ` +
        `context. LLMs normalise reading internally — they "see" the Latin word that the attacker ` +
        `intended — while human reviewers scrutinising the raw bytes see only Unicode "noise".`,
    });

    builder.impact({
      impact_type: "cross-agent-propagation",
      scope: "ai-client",
      exploitability: "moderate",
      scenario:
        `Prompt-injection payload written with confusable substitution bypasses lexical filters ` +
        `("ignore all prior" → "ignоrе аll priоr") while remaining fully legible to the LLM. ` +
        `Once the AI follows the injected instruction, a compromised tool can be invoked.`,
    });

    builder.factor(
      "homoglyph_density",
      Math.min(0.05 + a.hits.length * 0.02, 0.18),
      `${a.hits.length} homoglyphs in a ${a.codepoint_count}-codepoint description ` +
        `(density = ${((a.hits.length / Math.max(a.codepoint_count, 1)) * 100).toFixed(1)}%)`,
    );

    builder.factor(
      "cross_script_distribution",
      a.lookalike_scripts.length > 1 ? 0.12 : 0.05,
      `Confusables drawn from ${a.lookalike_scripts.length} distinct script block(s) — ` +
        `coordinated substitution rather than accidental mixing`,
    );

    builder.reference({
      id: "AML.T0054",
      title: "MITRE ATLAS — LLM Prompt Injection",
      url: "https://atlas.mitre.org/techniques/AML.T0054",
      relevance:
        `Confusable-encoded injection is an established prompt-injection variant — the visible ` +
        `payload differs from what the LLM reads after internal canonicalisation.`,
    });

    for (const s of descriptionVerificationSteps(t.tool_name, a)) {
      builder.verification(s);
    }

    const chain = builder.build();
    chain.confidence = capConfidence(chain.confidence);

    out.push({
      rule_id: RULE_ID,
      severity: a.hits.length >= 6 ? "critical" : "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    });
  }

  // ──────────────────── shadow-collision finding ──────────────

  private emitShadowCollisionFinding(
    c: {
      left_tool_name: string;
      right_tool_name: string;
      normalised_form: string;
    },
    out: RuleResult[],
  ): void {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: toolLoc(c.left_tool_name),
      observed:
        `Collision between tool "${c.left_tool_name}" and tool "${c.right_tool_name}" — ` +
        `both names normalise to "${c.normalised_form}" yet are distinct raw strings`,
      rationale:
        `Two tools in the same MCP server have names that are visually indistinguishable after ` +
        `TR39 confusable normalisation. The AI client routes by raw-string equality while the ` +
        `human reviewer routes by visual identity — the two disagree.`,
    });

    builder.propagation({
      propagation_type: "cross-tool-flow",
      location: TOOL_CAPABILITY_LOC,
      observed:
        `Server tool-registry (capability:tools) — AI client sees two tools with identical rendered names. Tool selection by name is ` +
        `undefined — which entry the client routes to depends on implementation details ` +
        `(insertion order, hash iteration) that are outside the user's or the reviewer's control.`,
    });

    builder.sink({
      sink_type: "privilege-grant",
      location: TOOL_CAPABILITY_LOC,
      observed:
        `AI-client tool-invocation (capability:tools) — for the rendered name "${c.normalised_form}" can be routed to either tool; ` +
        `the attacker-controlled tool captures the user's parameters and privileges whenever ` +
        `its entry is selected.`,
    });

    builder.factor(
      "exact_normalisation_collision",
      0.25,
      `Strict equality on the normalised form: both "${c.left_tool_name}" and "${c.right_tool_name}" ` +
        `→ "${c.normalised_form}"`,
    );

    builder.reference({
      id: "CWE-1007",
      title: "Insufficient Visual Distinction of Homoglyphs Before Rendering",
      url: "https://cwe.mitre.org/data/definitions/1007.html",
      relevance:
        `Collision on the rendered glyph sequence while the raw codepoints differ — the canonical ` +
        `CWE-1007 condition.`,
    });

    for (const s of shadowCollisionVerificationSteps(
      c.left_tool_name,
      c.right_tool_name,
      c.normalised_form,
    )) {
      builder.verification(s);
    }

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
}

registerTypedRuleV2(new UnicodeHomoglyphRuleV2());
