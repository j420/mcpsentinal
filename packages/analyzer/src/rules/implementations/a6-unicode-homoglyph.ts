/**
 * A6 — Unicode Homoglyph Attack Detection
 * A7 — Zero-Width Character Injection Detection
 *
 * REPLACES both YAML regex rules with comprehensive Unicode analysis.
 *
 * Old behavior: Regex pattern matching for known Cyrillic ranges.
 * New behavior: Full codepoint-level analysis with:
 * - Cyrillic/Greek/Armenian/Georgian homoglyph detection
 * - Fullwidth Latin detection
 * - Mathematical Alphanumeric Symbol detection
 * - Zero-width character detection (15 categories)
 * - Bidirectional override detection
 * - Tag character extraction (hidden ASCII messages)
 * - Mixed-script analysis
 * - Unicode confusable normalization for shadow tool detection
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import {
  analyzeUnicode,
  extractTagMessage,
  normalizeConfusables,
  type UnicodeIssueType,
} from "../analyzers/unicode.js";
import { EvidenceChainBuilder } from "../../evidence.js";

// --- A6: Homoglyph Attack ---

class UnicodeHomoglyphRule implements TypedRule {
  readonly id = "A6";
  readonly name = "Unicode Homoglyph Attack";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    for (const tool of context.tools) {
      // Analyze tool name (critical — this is the primary identifier)
      const nameResult = analyzeUnicode(tool.name);
      if (nameResult.has_issues) {
        const homoglyphs = nameResult.issues.filter(
          (i) =>
            i.type === "homoglyph" ||
            i.type === "confusable_whole_script" ||
            i.type === "mixed_script"
        );

        if (homoglyphs.length > 0) {
          const normalizedName = normalizeConfusables(tool.name);
          const isDifferentAfterNormalization = normalizedName !== tool.name;

          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool name: "${tool.name}"`,
              observed: homoglyphs.map((h) => h.description).join("; "),
              rationale:
                "Tool name contains non-Latin Unicode characters that are visually identical to Latin letters. " +
                "Tool names are external content registered by server authors and processed by AI clients as trusted identifiers.",
            })
            .propagation({
              propagation_type: "description-directive",
              location: `tool registry / AI client tool selection`,
              observed: `AI client receives tool name "${tool.name}" and treats it as a unique identifier for tool invocation`,
            })
            .sink({
              sink_type: "privilege-grant",
              location: `AI client tool invocation`,
              observed:
                `Identity confusion: AI client cannot distinguish "${tool.name}" from ` +
                `"${normalizedName}" — invokes attacker tool with user credentials`,
              cve_precedent: "CWE-1007",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: "tool registration / MCP client",
              detail:
                "No Unicode normalization or script validation on tool names — mixed-script identifiers are accepted without warning",
            })
            .impact({
              impact_type: "credential-theft",
              scope: "ai-client",
              exploitability: "trivial",
              scenario:
                "An attacker registers a tool with Cyrillic characters visually identical to a trusted tool name. " +
                "The AI client cannot distinguish the malicious tool from the legitimate one, causing it to invoke " +
                "the attacker's tool with the user's credentials and data.",
            })
            .factor(
              "homoglyph_detected",
              0.15,
              `${homoglyphs.length} homoglyph character(s) found in tool name`
            )
            .factor(
              isDifferentAfterNormalization ? "normalization_reveals_impersonation" : "normalization_unchanged",
              isDifferentAfterNormalization ? 0.15 : -0.1,
              isDifferentAfterNormalization
                ? `Name normalizes to "${normalizedName}" — visually impersonates a Latin-only identifier`
                : "Name unchanged after normalization — less likely to be impersonation"
            )
            .reference({
              id: "CWE-1007",
              title: "Insufficient Visual Distinction of Homoglyphs",
              url: "https://cwe.mitre.org/data/definitions/1007.html",
              relevance:
                "Tool name uses Unicode homoglyphs to create visual confusion between identifiers, " +
                "matching CWE-1007 (Insufficient Visual Distinction of Homoglyphs Before Rendering)",
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                "Examine the tool name character by character using a hex editor or Unicode inspector. " +
                "Check each codepoint against the Unicode Character Database to confirm script membership. " +
                "Latin 'a' is U+0061; Cyrillic 'а' is U+0430 — they render identically but are different characters.",
              target: `tool name: "${tool.name}"`,
              expected_observation:
                `One or more characters belong to non-Latin scripts (Cyrillic, Greek, Mathematical Alphanumerics, Fullwidth Latin). ` +
                `Scripts detected: ${[...nameResult.scripts_detected].join(", ")}.`,
            })
            .verification({
              step_type: "compare-baseline",
              instruction:
                "Compare the tool name against known legitimate tool names in the same server or ecosystem. " +
                "Apply Unicode confusable normalization (UAX #39) to both names and check for collisions. " +
                "If the normalized form matches a known tool, this confirms homoglyph-based impersonation.",
              target: `normalized form: "${normalizedName}"`,
              expected_observation:
                isDifferentAfterNormalization
                  ? `After normalization, the name becomes "${normalizedName}" which may match a legitimate tool — confirming visual impersonation.`
                  : "Name is unchanged after normalization but still contains mixed scripts, suggesting potential confusion.",
            })
            .build();

          findings.push({
            rule_id: "A6",
            severity: "critical",
            evidence:
              `Tool name "${tool.name}" contains ${homoglyphs.length} homoglyph character(s). ` +
              `${homoglyphs.map((h) => h.description).join("; ")}. ` +
              (isDifferentAfterNormalization
                ? `After confusable normalization: "${normalizedName}" — ` +
                  `this name visually impersonates a Latin-only identifier.`
                : `Name unchanged after normalization.`) +
              ` Scripts detected: ${[...nameResult.scripts_detected].join(", ")}.`,
            remediation:
              "Tool names must use only ASCII Latin characters (a-z, A-Z, 0-9, underscore). " +
              "Non-Latin characters that look identical to Latin letters (Cyrillic а=a, Greek Ο=O) " +
              "enable visual impersonation of legitimate tools. " +
              "Reject tool registrations containing non-Latin script characters in identifiers.",
            owasp_category: "MCP02-tool-poisoning",
            mitre_technique: "AML.T0054",
            confidence:
              isDifferentAfterNormalization
                ? 0.95
                : Math.max(...homoglyphs.map((h) => h.confidence)),
            metadata: {
              original_name: tool.name,
              normalized_name: normalizedName,
              scripts_detected: [...nameResult.scripts_detected],
              homoglyph_count: homoglyphs.length,
              suspicious_codepoints: nameResult.suspicious_codepoint_count,
              issues: homoglyphs.map((h) => ({
                type: h.type,
                codepoints: h.codepoints.map(
                  (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
                ),
                description: h.description,
              })),
              evidence_chain: chain,
            },
          });
        }
      }

      // Analyze tool description for homoglyphs (medium severity — less critical than name)
      if (tool.description) {
        const descResult = analyzeUnicode(tool.description);
        const descHomoglyphs = descResult.issues.filter(
          (i) => i.type === "homoglyph" || i.type === "confusable_whole_script"
        );

        if (descHomoglyphs.length >= 3) {
          // Only flag if significant number of homoglyphs in description
          findings.push({
            rule_id: "A6",
            severity: "high",
            evidence:
              `Tool "${tool.name}" description contains ${descHomoglyphs.length} homoglyph characters. ` +
              `Mixed scripts: ${[...descResult.scripts_detected].join(", ")}. ` +
              `This may indicate an attempt to hide injection payloads using ` +
              `visually similar characters from non-Latin scripts.`,
            remediation:
              "Tool descriptions should use consistent Unicode scripts. " +
              "Multiple homoglyph characters across Latin/Cyrillic/Greek boundaries " +
              "suggest intentional obfuscation.",
            owasp_category: "MCP02-tool-poisoning",
            mitre_technique: "AML.T0054",
            confidence: Math.min(0.9, 0.5 + descHomoglyphs.length * 0.1),
          });
        }
      }

      // Shadow tool detection: check if normalized name matches another tool
      const normalizedName = normalizeConfusables(tool.name);
      for (const otherTool of context.tools) {
        if (otherTool.name === tool.name) continue;
        const otherNormalized = normalizeConfusables(otherTool.name);
        if (normalizedName === otherNormalized && tool.name !== otherTool.name) {
          findings.push({
            rule_id: "A6",
            severity: "critical",
            evidence:
              `Tool "${tool.name}" and tool "${otherTool.name}" are visually identical ` +
              `after Unicode confusable normalization (both normalize to "${normalizedName}"). ` +
              `This is a homoglyph-based tool shadowing attack.`,
            remediation:
              "Remove the tool with non-Latin characters. Both tool names " +
              "appear identical to humans but are different strings, " +
              "enabling impersonation.",
            owasp_category: "MCP02-tool-poisoning",
            mitre_technique: "AML.T0054",
            confidence: 0.99,
          });
        }
      }
    }

    return findings;
  }
}

// --- A7: Zero-Width Character Injection ---

class ZeroWidthInjectionRule implements TypedRule {
  readonly id = "A7";
  readonly name = "Zero-Width Character Injection";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];
    const issueTypeLabels: Record<UnicodeIssueType, string> = {
      zero_width: "zero-width character",
      bidi_override: "bidirectional override",
      tag_character: "tag character (hidden ASCII)",
      variation_selector: "variation selector",
      invisible_operator: "invisible formatting character",
      homoglyph: "homoglyph",
      mixed_script: "mixed script",
      confusable_whole_script: "confusable",
    };

    // Types relevant for tool names (variation selectors always suspicious in identifiers)
    const nameRelevantTypes: UnicodeIssueType[] = [
      "zero_width",
      "bidi_override",
      "tag_character",
      "variation_selector",
      "invisible_operator",
    ];

    // Types relevant for descriptions (variation selectors after emoji are normal)
    const descRelevantTypes: UnicodeIssueType[] = [
      "zero_width",
      "bidi_override",
      "tag_character",
      "invisible_operator",
    ];

    for (const tool of context.tools) {
      // Check tool name for invisible characters
      const nameResult = analyzeUnicode(tool.name);
      const nameInvisible = nameResult.issues.filter((i) =>
        nameRelevantTypes.includes(i.type)
      );

      if (nameInvisible.length > 0) {
        findings.push({
          rule_id: "A7",
          severity: "critical",
          evidence:
            `Tool name "${tool.name}" contains ${nameInvisible.length} invisible character(s): ` +
            `${nameInvisible.map((i) => `${issueTypeLabels[i.type]} ${i.description}`).join("; ")}. ` +
            `These characters are invisible to human reviewers but processed by LLMs, ` +
            `enabling hidden instructions or identifier manipulation.`,
          remediation:
            "Strip all Unicode control characters, zero-width characters, " +
            "bidirectional overrides, and tag characters from tool names. " +
            "Only allow visible ASCII and common Unicode letter categories.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0054",
          confidence: 0.95,
          metadata: {
            invisible_chars: nameInvisible.map((i) => ({
              type: i.type,
              codepoints: i.codepoints.map(
                (cp) => `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`
              ),
              positions: i.positions,
            })),
          },
        });
      }

      // Check tool description for invisible characters
      if (tool.description) {
        const descResult = analyzeUnicode(tool.description);
        const descInvisible = descResult.issues.filter((i) =>
          descRelevantTypes.includes(i.type)
        );

        if (descInvisible.length > 0) {
          // Check for tag characters hiding ASCII messages
          const hiddenMessage = extractTagMessage(tool.description);

          const chain = new EvidenceChainBuilder()
            .source({
              source_type: "external-content",
              location: `tool "${tool.name}" description`,
              observed: descInvisible.map((i) => issueTypeLabels[i.type]).join(", "),
              rationale:
                "Tool description contains invisible Unicode characters that are not rendered visually " +
                "but are processed by AI models as part of the input text. These characters are injected " +
                "by the server author and consumed by the AI client without human review.",
            })
            .propagation({
              propagation_type: "description-directive",
              location: `AI client context window`,
              observed:
                "Invisible characters are included in the tool description text sent to the AI model " +
                "as part of tool selection context — the model processes them as instructions",
            })
            .sink({
              sink_type: "code-evaluation",
              location: `AI model instruction processing`,
              observed: hiddenMessage
                ? `Hidden instructions decoded from tag characters: "${hiddenMessage}"`
                : "Invisible characters may encode directives processed by the AI model but invisible to human auditors",
            })
            .mitigation({
              mitigation_type: "input-validation",
              present: false,
              location: "tool description ingestion / MCP client",
              detail:
                "No Unicode normalization or invisible character stripping applied to tool descriptions before AI processing",
            })
            .impact({
              impact_type: "cross-agent-propagation",
              scope: "ai-client",
              exploitability: hiddenMessage ? "trivial" : "moderate",
              scenario:
                "Invisible Unicode characters embed instructions that are processed by the AI model but invisible " +
                "to human reviewers. A security auditor examining the tool description sees benign text while the " +
                "model receives additional directives.",
            })
            .factor(
              "invisible_chars_in_description",
              0.1,
              `${descInvisible.length} invisible character(s) found in tool description`
            )
            .factor(
              hiddenMessage ? "hidden_message_extracted" : "no_hidden_message",
              hiddenMessage ? 0.25 : 0.0,
              hiddenMessage
                ? `Tag characters decode to hidden ASCII message: "${hiddenMessage}"`
                : "No tag-character hidden message detected (other invisible chars still present)"
            )
            .reference({
              id: "AML.T0054",
              title: "MITRE ATLAS — LLM Prompt Injection",
              url: "https://atlas.mitre.org/techniques/AML.T0054",
              relevance:
                "Invisible Unicode characters are a steganographic prompt injection vector — " +
                "instructions are embedded in metadata fields that appear clean to human reviewers " +
                "but contain directives processed by the AI model",
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                "Perform a hex dump of the tool description text using `xxd` or a Unicode inspector tool. " +
                "Search for codepoints in the following ranges: U+200B-U+200F (zero-width), U+202A-U+202E (bidi overrides), " +
                "U+2060-U+2064 (invisible operators), U+E0001-U+E007F (tag characters), U+FE00-U+FE0F (variation selectors). " +
                "Count the total number of invisible characters and note their positions in the text.",
              target: `tool "${tool.name}" description (${tool.description.length} chars)`,
              expected_observation:
                `${descInvisible.length} invisible character(s) at positions not adjacent to emoji or legitimate formatting contexts. ` +
                `Types found: ${[...new Set(descInvisible.map((i) => i.type))].join(", ")}.`,
            })
            .verification({
              step_type: "inspect-description",
              instruction:
                hiddenMessage
                  ? `Extract tag characters (U+E0001-U+E007F) and decode them as ASCII by subtracting 0xE0000 from each codepoint. ` +
                    `Verify the decoded message matches the detected hidden payload. Check whether the decoded text contains ` +
                    `instructions, URLs, or directives that would alter AI behavior.`
                  : `Remove all invisible characters from the description and compare the cleaned version with the original. ` +
                    `Check whether the visible text changes meaning or layout after stripping. Verify whether the invisible ` +
                    `characters appear at positions that could split words or alter token boundaries for the AI model.`,
              target: `tool "${tool.name}" description — invisible character positions`,
              expected_observation: hiddenMessage
                ? `Tag characters decode to: "${hiddenMessage}" — confirming steganographic injection.`
                : "Invisible characters are present at suspicious positions, not adjacent to emoji or legitimate formatting.",
            })
            .build();

          findings.push({
            rule_id: "A7",
            severity: hiddenMessage ? "critical" : "high",
            evidence:
              `Tool "${tool.name}" description contains ${descInvisible.length} invisible character(s): ` +
              `${descInvisible.map((i) => issueTypeLabels[i.type]).join(", ")}. ` +
              (hiddenMessage
                ? `HIDDEN MESSAGE extracted from tag characters: "${hiddenMessage}". ` +
                  `This is a steganographic injection — instructions hidden in invisible Unicode.`
                : `These may hide injection payloads invisible to human review.`),
            remediation:
              "Strip all invisible Unicode characters from tool descriptions. " +
              "Tag characters (U+E0001–U+E007F) can encode entire hidden messages. " +
              "Bidirectional overrides (U+202A–U+202E) reorder displayed text.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: hiddenMessage ? 0.99 : 0.85,
            metadata: {
              hidden_message: hiddenMessage,
              invisible_count: descInvisible.length,
              types_found: [...new Set(descInvisible.map((i) => i.type))],
              evidence_chain: chain,
            },
          });
        }

        // Check for bidirectional override specifically (visual text reordering)
        const bidiIssues = descResult.issues.filter(
          (i) => i.type === "bidi_override"
        );
        if (bidiIssues.length > 0) {
          findings.push({
            rule_id: "A7",
            severity: "critical",
            evidence:
              `Tool "${tool.name}" description contains ${bidiIssues.length} bidirectional override character(s). ` +
              `RTL override (U+202E) reverses displayed text direction — the text humans read ` +
              `is the REVERSE of what the LLM processes. This enables displaying a safe description ` +
              `to reviewers while the LLM receives a different instruction.`,
            remediation:
              "Strip all bidirectional control characters (U+200E–U+200F, U+202A–U+202E, U+2066–U+2069) " +
              "from tool metadata.",
            owasp_category: "MCP01-prompt-injection",
            mitre_technique: "AML.T0054",
            confidence: 0.95,
          });
        }
      }

      // Check parameter descriptions for invisible characters
      if (tool.input_schema?.properties) {
        const props = tool.input_schema.properties as Record<
          string,
          Record<string, unknown>
        >;
        for (const [paramName, paramDef] of Object.entries(props)) {
          const paramDesc = (paramDef.description as string) || "";
          if (!paramDesc) continue;

          const paramResult = analyzeUnicode(paramDesc);
          const paramInvisible = paramResult.issues.filter((i) =>
            descRelevantTypes.includes(i.type)
          );

          if (paramInvisible.length > 0) {
            findings.push({
              rule_id: "A7",
              severity: "high",
              evidence:
                `Tool "${tool.name}", parameter "${paramName}" description contains ` +
                `${paramInvisible.length} invisible character(s). ` +
                `Parameter descriptions are a secondary injection surface — ` +
                `LLMs read them when deciding how to fill arguments.`,
              remediation:
                "Strip invisible characters from parameter descriptions.",
              owasp_category: "MCP01-prompt-injection",
              mitre_technique: "AML.T0054",
              confidence: 0.8,
            });
          }
        }
      }
    }

    return findings;
  }
}

registerTypedRule(new UnicodeHomoglyphRule());
registerTypedRule(new ZeroWidthInjectionRule());
