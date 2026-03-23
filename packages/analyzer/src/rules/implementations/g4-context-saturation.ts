/**
 * G4 — Context Window Saturation Attack (Statistical Analysis)
 *
 * REPLACES the YAML composite rule with entropy-based statistical analysis.
 *
 * Old behavior: Simple length threshold + character-per-parameter ratio.
 * New behavior: Multi-metric statistical analysis that detects sophisticated
 * padding attacks designed to push safety instructions below the model's
 * effective attention threshold.
 *
 * Detection metrics:
 * 1. Description-to-parameter entropy ratio — padding text has lower entropy
 *    than functional description text
 * 2. Tail injection detection — entropy spike in the last 20% of a long
 *    description (payload hidden after padding)
 * 3. Compression ratio anomaly — padding is highly compressible (repetitive)
 *    while functional text has moderate compressibility
 * 4. Token density estimation — characters per semantic unit
 * 5. Information-to-noise ratio — how much of the description is actually
 *    informative vs. filler
 */

import type { TypedRule, TypedFinding } from "../base.js";
import { registerTypedRule } from "../base.js";
import type { AnalysisContext } from "../../engine.js";
import {
  shannonEntropy,
  compressionRatio,
  slidingWindowEntropy,
  classifyContent,
} from "../analyzers/entropy.js";

/** Thresholds for context saturation detection */
const THRESHOLDS = {
  /** Minimum description length to analyze (below this, saturation isn't possible) */
  min_length: 500,
  /** Description length that triggers high suspicion */
  high_suspicion_length: 3000,
  /** Maximum reasonable chars per parameter for legitimate documentation */
  max_chars_per_param: 500,
  /** Compression ratio below which text is suspiciously repetitive */
  padding_compression_threshold: 0.25,
  /** Entropy below which text is suspiciously uniform */
  padding_entropy_threshold: 3.5,
  /** Entropy difference threshold between head and tail of description */
  tail_injection_entropy_diff: 1.5,
};

class ContextSaturationRule implements TypedRule {
  readonly id = "G4";
  readonly name = "Context Window Saturation Attack (Statistical)";

  analyze(context: AnalysisContext): TypedFinding[] {
    const findings: TypedFinding[] = [];

    for (const tool of context.tools) {
      if (!tool.description || tool.description.length < THRESHOLDS.min_length) continue;

      const desc = tool.description;
      const paramCount = tool.input_schema?.properties
        ? Object.keys(tool.input_schema.properties as object).length
        : 0;

      // Metric 1: Global entropy analysis
      const globalEntropy = shannonEntropy(desc);
      const globalCompression = compressionRatio(desc);
      const globalClassification = classifyContent(desc);

      // Metric 2: Head vs tail entropy comparison
      const headSize = Math.floor(desc.length * 0.3); // First 30%
      const tailSize = Math.floor(desc.length * 0.2); // Last 20%
      const headEntropy = shannonEntropy(desc.slice(0, headSize));
      const tailEntropy = shannonEntropy(desc.slice(-tailSize));
      const entropyDiff = Math.abs(tailEntropy - headEntropy);

      // Metric 3: Chars per parameter ratio
      const charsPerParam = paramCount > 0 ? desc.length / paramCount : desc.length;

      // Metric 4: Repetition analysis via compression
      // Padding attacks use repetitive text to inflate description length
      const isPaddingDetected =
        globalCompression < THRESHOLDS.padding_compression_threshold &&
        desc.length > THRESHOLDS.high_suspicion_length;

      // Metric 5: Sliding window for entropy anomalies in tail
      const tailText = desc.slice(-tailSize);
      const tailAnomalies = slidingWindowEntropy(tailText, 48, 12, 5.0);

      // --- Decision logic ---

      const issues: string[] = [];
      let severity: "critical" | "high" | "medium" = "medium";
      let confidence = 0.0;

      // Check 1: Abnormally long + low entropy (padding)
      if (
        desc.length > THRESHOLDS.high_suspicion_length &&
        globalEntropy < THRESHOLDS.padding_entropy_threshold
      ) {
        issues.push(
          `Description is ${desc.length} chars with low entropy ` +
          `(${globalEntropy.toFixed(2)} bits/char — padding text is typically <3.5, ` +
          `functional documentation is 4.0–5.5)`
        );
        confidence += 0.3;
      }

      // Check 2: Disproportionate length per parameter
      if (charsPerParam > THRESHOLDS.max_chars_per_param && desc.length > 1000) {
        issues.push(
          `${charsPerParam.toFixed(0)} chars/parameter ` +
          `(${desc.length} total / ${paramCount || 1} params — ` +
          `legitimate tools average 50-150 chars/param)`
        );
        confidence += 0.2;
      }

      // Check 3: Tail injection (entropy spike in last 20%)
      if (
        entropyDiff > THRESHOLDS.tail_injection_entropy_diff &&
        tailEntropy > headEntropy &&
        desc.length > 1000
      ) {
        issues.push(
          `Tail injection detected: head entropy=${headEntropy.toFixed(2)}, ` +
          `tail entropy=${tailEntropy.toFixed(2)} (diff=${entropyDiff.toFixed(2)}). ` +
          `The last 20% of the description has significantly higher entropy — ` +
          `a payload hidden after padding exploits LLM recency bias`
        );
        confidence += 0.35;
        severity = "critical";
      }

      // Check 4: Padding via repetition
      if (isPaddingDetected) {
        issues.push(
          `Compression ratio ${globalCompression.toFixed(3)} indicates highly repetitive content ` +
          `(functional text compresses to 0.3–0.6; this text is ${(globalCompression * 100).toFixed(0)}% ` +
          `of original size, indicating deliberate padding)`
        );
        confidence += 0.25;
        severity = severity === "critical" ? "critical" : "high";
      }

      // Check 5: High-entropy anomalies in tail region
      if (tailAnomalies.length > 0) {
        issues.push(
          `${tailAnomalies.length} high-entropy region(s) in tail: ` +
          tailAnomalies
            .map(
              (a) =>
                `${a.classification} at offset ${a.offset} ` +
                `(entropy=${a.entropy.toFixed(2)})`
            )
            .join("; ")
        );
        confidence += 0.2;
        severity = "critical";
      }

      // Only produce finding if multiple signals converge
      if (issues.length >= 2 && confidence >= 0.4) {
        findings.push({
          rule_id: "G4",
          severity,
          evidence:
            `[Statistical analysis] Tool "${tool.name}" shows ${issues.length} ` +
            `context saturation indicators: ${issues.join(". ")}. ` +
            `Combined confidence: ${(Math.min(confidence, 0.95) * 100).toFixed(0)}%.`,
          remediation:
            "Reduce description length to under 500 characters. " +
            "If detailed documentation is needed, link to external docs. " +
            "Context window saturation attacks pad descriptions to push " +
            "the AI client's safety instructions below its attention threshold, " +
            "then place a payload in the tail of the description.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0061",
          confidence: Math.min(confidence, 0.95),
          metadata: {
            analysis_type: "statistical_saturation",
            description_length: desc.length,
            param_count: paramCount,
            chars_per_param: charsPerParam,
            global_entropy: globalEntropy,
            global_compression: globalCompression,
            head_entropy: headEntropy,
            tail_entropy: tailEntropy,
            entropy_diff: entropyDiff,
            tail_anomaly_count: tailAnomalies.length,
            classification: globalClassification.classification,
            issue_count: issues.length,
          },
        });
      }
    }

    return findings;
  }
}

registerTypedRule(new ContextSaturationRule());
