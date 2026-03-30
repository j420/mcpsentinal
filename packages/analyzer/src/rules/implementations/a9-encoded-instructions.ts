/**
 * A9 — Encoded Instructions Detection (Entropy-Based)
 *
 * REPLACES the YAML regex rule with information-theoretic analysis.
 *
 * Old behavior: Regex patterns for known encoding signatures (base64 padding, %XX).
 * New behavior: Shannon entropy + compression ratio + sliding window to detect
 * ANY encoded/obfuscated content regardless of encoding scheme.
 *
 * Why entropy beats regex:
 * - Regex catches: base64, hex, URL-encoding
 * - Entropy catches: ALL of the above PLUS novel encodings, custom base-N schemes,
 *   XOR-obfuscated payloads, steganographic content, polymorphic injection
 *
 * Detection model:
 * 1. Global entropy of tool description — is the overall text suspicious?
 * 2. Sliding window entropy — are there HIGH-ENTROPY REGIONS embedded in normal text?
 * 3. Content classification — what TYPE of encoding is detected?
 * 4. Chi-squared uniformity — is the data statistically random?
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import type { Severity } from "@mcp-sentinel/database";
import {
  classifyContent,
  slidingWindowEntropy,
  shannonEntropy,
  type EntropyAnomaly,
  type EntropyClassification,
} from "../analyzers/entropy.js";
import { EvidenceChainBuilder } from "../../evidence.js";

const CLASSIFICATION_SEVERITY: Record<EntropyClassification, Severity> = {
  base64: "critical",
  hex_encoded: "high",
  url_encoded: "high",
  encrypted_or_random: "critical",
  compressed: "critical",
  mixed: "medium",
  source_code: "informational",
  natural_language: "informational",
  unknown: "low",
};

class EncodedInstructionsRule implements TypedRule {
  readonly id = "A9";
  readonly name = "Encoded Instructions in Description (Entropy-Based)";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    for (const tool of context.tools) {
      if (!tool.description || tool.description.length < 20) continue;

      // Phase 1: Global entropy analysis
      const globalResult = classifyContent(tool.description);

      if (
        globalResult.classification !== "natural_language" &&
        globalResult.classification !== "source_code" &&
        globalResult.classification !== "unknown" &&
        globalResult.confidence >= 0.6
      ) {
        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool "${tool.name}" description (${tool.description.length} chars)`,
            observed:
              `Entire description classified as "${globalResult.classification}" — ` +
              `Shannon entropy: ${globalResult.shannon_entropy.toFixed(2)} bits/char`,
            rationale:
              "Tool description contains encoded or obfuscated content instead of natural language. " +
              "Descriptions are external content authored by the server publisher and consumed by AI clients " +
              "as trusted context for tool selection and invocation.",
          })
          .propagation({
            propagation_type: "description-directive",
            location: "AI client context window",
            observed:
              "Encoded payload in the description is sent to the AI model as part of tool metadata. " +
              "AI models with decoding capabilities (base64, hex, URL) may decode and execute the hidden instructions.",
          })
          .sink({
            sink_type: "code-evaluation",
            location: "AI model instruction processing",
            observed:
              `Encoded content (${globalResult.classification}) bypasses human review because ` +
              `the encoded text appears as random characters to reviewers, but the AI model may ` +
              `decode and execute them as instructions`,
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: "tool description ingestion / MCP client",
            detail:
              "No entropy analysis or encoding detection applied to tool descriptions before AI processing",
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: "moderate",
            scenario:
              "Base64, URL-encoded, or HTML-entity encoded instructions are embedded in the tool description. " +
              "These bypass human review because the encoded text appears as random characters, but the AI model " +
              "may decode and execute them as instructions.",
          })
          .factor(
            "global_entropy_anomaly",
            0.15,
            `Shannon entropy ${globalResult.shannon_entropy.toFixed(2)} bits/char is outside natural language range (3.0-4.5)`
          )
          .factor(
            "chi_squared_uniformity",
            globalResult.chi_squared_p_value > 0.05 ? 0.1 : -0.05,
            globalResult.chi_squared_p_value > 0.05
              ? `Chi-squared p-value ${globalResult.chi_squared_p_value.toFixed(4)} > 0.05 — consistent with random/encoded data`
              : `Chi-squared p-value ${globalResult.chi_squared_p_value.toFixed(4)} < 0.05 — not uniformly random`
          )
          .reference({
            id: "AML.T0054",
            title: "MITRE ATLAS — LLM Prompt Injection",
            url: "https://atlas.mitre.org/techniques/AML.T0054",
            relevance:
              "Encoded instructions in tool descriptions are an indirect prompt injection technique. " +
              "The payload is obfuscated to evade human review while remaining decodable by AI models.",
          })
          .verification({
            step_type: "inspect-description",
            instruction:
              "Examine the tool description text for encoded content. Attempt to decode using common schemes: " +
              "base64 (look for [A-Za-z0-9+/]= padding), URL encoding (look for %XX sequences), " +
              "hex encoding (look for \\x or 0x prefixes), and HTML entities (look for &#x or &amp; patterns). " +
              "Use `echo '<payload>' | base64 -d` or equivalent to attempt decoding suspicious blocks.",
            target: `tool "${tool.name}" description`,
            expected_observation:
              `Description classified as "${globalResult.classification}" with entropy ` +
              `${globalResult.shannon_entropy.toFixed(2)} bits/char. Decoding should reveal hidden text instructions.`,
          })
          .verification({
            step_type: "test-input",
            instruction:
              "Extract the suspected encoded payload and attempt to decode it with each encoding scheme. " +
              "If decoding produces readable text, examine whether the decoded content contains AI directives, " +
              "system prompt overrides, role injection patterns, or exfiltration instructions. Compare the decoded " +
              "text against known prompt injection patterns (role claims, instruction overrides, data exfiltration URLs).",
            target: `decoded payload from tool "${tool.name}" description`,
            expected_observation:
              "Decoded content reveals instructions that would alter AI behavior — " +
              "confirming the encoded content is a prompt injection payload hidden from human review.",
          })
          .build();

        findings.push({
          rule_id: "A9",
          severity: CLASSIFICATION_SEVERITY[globalResult.classification] || "medium",
          evidence:
            `Tool "${tool.name}" description classified as "${globalResult.classification}" ` +
            `(confidence: ${(globalResult.confidence * 100).toFixed(0)}%). ` +
            `Shannon entropy: ${globalResult.shannon_entropy.toFixed(2)} bits/char ` +
            `(natural language: 3.0–4.5, base64: 5.7–6.0, encrypted: 7.5–8.0). ` +
            `Compression ratio: ${globalResult.compression_ratio.toFixed(3)} ` +
            `(0.0 = highly compressible, 1.0 = incompressible). ` +
            `Chi-squared p-value: ${globalResult.chi_squared_p_value.toFixed(4)} ` +
            `(>0.05 = consistent with random data).`,
          remediation:
            "Tool descriptions should be human-readable natural language. " +
            "Encoded content (base64, hex, encrypted blocks) hides instructions " +
            "from human reviewers while being decodable by LLMs. " +
            "Remove all encoded blocks from tool metadata.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0054",
          confidence: globalResult.confidence,
          metadata: {
            analysis_type: "global_entropy",
            shannon_entropy: globalResult.shannon_entropy,
            chi_squared: globalResult.chi_squared,
            chi_squared_p_value: globalResult.chi_squared_p_value,
            compression_ratio: globalResult.compression_ratio,
            classification: globalResult.classification,
            evidence_chain: chain,
          },
        });
      }

      // Phase 2: Sliding window analysis — detect embedded encoded regions
      const anomalies = slidingWindowEntropy(tool.description);

      for (const anomaly of anomalies) {
        // Skip if it's just source code or natural language
        if (
          anomaly.classification === "natural_language" ||
          anomaly.classification === "source_code"
        )
          continue;

        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool "${tool.name}" description, offset ${anomaly.offset} (${anomaly.length} chars)`,
            observed: anomaly.text.slice(0, 120),
            rationale:
              "A high-entropy region is embedded within otherwise normal description text. " +
              "This is a signature pattern of encoded instructions hidden in legitimate-looking content.",
          })
          .propagation({
            propagation_type: "description-directive",
            location: "AI client context window",
            observed:
              `Encoded island (${anomaly.classification}) at offset ${anomaly.offset} is included ` +
              `in the full description text sent to the AI model`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: "AI model instruction processing",
            observed:
              `Embedded ${anomaly.classification} region with entropy ${anomaly.entropy.toFixed(2)} bits/char — ` +
              `stands out from surrounding natural language text`,
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: "moderate",
            scenario:
              "An encoded payload is embedded within an otherwise normal tool description. " +
              "The surrounding text appears benign to human reviewers, while the encoded region " +
              "contains instructions that the AI model can decode and follow.",
          })
          .factor(
            "embedded_entropy_island",
            0.15,
            `Region entropy ${anomaly.entropy.toFixed(2)} bits/char significantly exceeds surrounding text`
          )
          .verification({
            step_type: "inspect-description",
            instruction:
              `Extract the ${anomaly.length}-character region starting at offset ${anomaly.offset} in the tool description. ` +
              `Compute its Shannon entropy independently and compare against the surrounding text entropy. ` +
              `A difference of more than 1.5 bits/char confirms an entropy island — encoded content embedded in natural language.`,
            target: `tool "${tool.name}" description, chars ${anomaly.offset}-${anomaly.offset + anomaly.length}`,
            expected_observation:
              `Region classified as "${anomaly.classification}" with entropy ${anomaly.entropy.toFixed(2)} bits/char, ` +
              `significantly higher than surrounding natural language text (typically 3.0-4.5 bits/char).`,
          })
          .verification({
            step_type: "test-input",
            instruction:
              `Attempt to decode the extracted region using ${anomaly.classification} decoding. ` +
              `For base64: strip whitespace and run through a base64 decoder. For hex: interpret as hex bytes. ` +
              `For URL-encoding: decode %XX sequences. Check if the decoded output contains readable text, ` +
              `especially AI directives or prompt injection patterns.`,
            target: `extracted region: "${anomaly.text.slice(0, 80)}${anomaly.text.length > 80 ? "..." : ""}"`,
            expected_observation:
              "Decoding reveals hidden instructions or payload content that was invisible in the encoded form.",
          })
          .build();

        findings.push({
          rule_id: "A9",
          severity: CLASSIFICATION_SEVERITY[anomaly.classification] || "medium",
          evidence:
            `Tool "${tool.name}" description contains embedded ${anomaly.classification} region ` +
            `at offset ${anomaly.offset} (${anomaly.length} chars). ` +
            `Region entropy: ${anomaly.entropy.toFixed(2)} bits/char ` +
            `vs surrounding text. ` +
            `Content: "${anomaly.text.slice(0, 100)}${anomaly.text.length > 100 ? "..." : ""}". ` +
            `This is a high-entropy island embedded in normal description text — ` +
            `a signature of hidden encoded instructions.`,
          remediation:
            "Remove the encoded region from the tool description. " +
            "Legitimate descriptions don't contain embedded base64 blocks, " +
            "hex sequences, or encrypted payloads.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0054",
          confidence: anomaly.confidence,
          metadata: {
            analysis_type: "sliding_window",
            offset: anomaly.offset,
            length: anomaly.length,
            region_entropy: anomaly.entropy,
            classification: anomaly.classification,
            evidence_chain: chain,
          },
        });
      }

      // Phase 3: Check parameter descriptions too
      if (tool.input_schema?.properties) {
        const props = tool.input_schema.properties as Record<
          string,
          Record<string, unknown>
        >;
        for (const [paramName, paramDef] of Object.entries(props)) {
          const paramDesc = (paramDef.description as string) || "";
          if (paramDesc.length < 30) continue;

          const paramEntropy = shannonEntropy(paramDesc);
          if (paramEntropy > 5.5) {
            const paramResult = classifyContent(paramDesc);
            if (
              paramResult.classification !== "natural_language" &&
              paramResult.classification !== "source_code" &&
              paramResult.confidence >= 0.5
            ) {
              const a9ParamChain = new EvidenceChainBuilder()
                .source({
                  source_type: "external-content",
                  location: `tool:${tool.name}:param:${paramName}:description`,
                  observed: `Entropy: ${paramEntropy.toFixed(2)} bits/char, classified as "${paramResult.classification}"`,
                  rationale: "Parameter description has anomalous entropy suggesting encoded or obfuscated content",
                })
                .propagation({
                  propagation_type: "description-directive",
                  location: `tool:${tool.name}:param:${paramName}`,
                  observed: `High-entropy parameter description processed by AI for argument filling`,
                })
                .impact({
                  impact_type: "cross-agent-propagation",
                  scope: "ai-client",
                  exploitability: "moderate",
                  scenario: `Encoded instructions in parameter "${paramName}" of tool "${tool.name}" bypass human review`,
                })
                .factor("entropy_analysis", paramResult.confidence * 0.8 - 0.70, `Shannon entropy ${paramEntropy.toFixed(2)} bits/char`)
                .verification({
                  step_type: "inspect-description",
                  instruction: `Decode/inspect parameter "${paramName}" description for hidden instructions`,
                  target: `tool:${tool.name}:param:${paramName}`,
                  expected_observation: `Content classified as "${paramResult.classification}" with entropy ${paramEntropy.toFixed(2)}`,
                })
                .build();
              findings.push({
                rule_id: "A9",
                severity: "high",
                evidence:
                  `Tool "${tool.name}", parameter "${paramName}" description has ` +
                  `anomalous entropy: ${paramEntropy.toFixed(2)} bits/char ` +
                  `(classified as "${paramResult.classification}"). ` +
                  `Parameter descriptions are a secondary injection surface.`,
                remediation:
                  "Parameter descriptions should be plain text explanations.",
                owasp_category: "MCP01-prompt-injection",
                mitre_technique: "AML.T0054",
                confidence: paramResult.confidence * 0.8,
                metadata: { evidence_chain: a9ParamChain },
              });
            }
          }
        }
      }
    }

    return findings;
  }
}

registerTypedRule(new EncodedInstructionsRule());
