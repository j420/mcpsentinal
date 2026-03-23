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
