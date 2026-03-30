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
import { EvidenceChainBuilder } from "../../evidence.js";

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
        const clampedConfidence = Math.min(confidence, 0.95);

        const chain = new EvidenceChainBuilder()
          .source({
            source_type: "external-content",
            location: `tool "${tool.name}" description (${desc.length} chars)`,
            observed:
              `Oversized description: ${desc.length} chars, entropy ${globalEntropy.toFixed(2)} bits/char, ` +
              `compression ratio ${globalCompression.toFixed(3)}`,
            rationale:
              "Tool description is external content authored by the server publisher. An oversized description " +
              "with low entropy (repetitive padding) is designed to consume context window space, pushing the " +
              "AI client's safety instructions below its effective attention threshold.",
          })
          .propagation({
            propagation_type: "description-directive",
            location: "AI client context window",
            observed:
              `${desc.length}-character description occupies significant context window space. ` +
              `At ~4 chars/token, this consumes approximately ${Math.ceil(desc.length / 4)} tokens ` +
              `of the model's context budget.`,
          })
          .sink({
            sink_type: "code-evaluation",
            location: "AI model attention mechanism",
            observed:
              "Safety instructions positioned before this description in the context window are displaced " +
              "below the model's effective attention threshold — research shows models exhibit recency bias, " +
              "prioritizing content near the end of the context over earlier instructions",
          })
          .mitigation({
            mitigation_type: "input-validation",
            present: false,
            location: "tool description ingestion / MCP client",
            detail:
              "No description length limit or entropy-based content filtering applied. " +
              "Descriptions of any length are passed directly to the AI model context.",
          })
          .impact({
            impact_type: "cross-agent-propagation",
            scope: "ai-client",
            exploitability: tailAnomalies.length > 0 ? "trivial" : "moderate",
            scenario:
              "An oversized tool description pushes safety instructions below the model's effective attention window. " +
              "Research shows recency bias causes models to prioritize content at the end of their context, so safety " +
              "instructions near the start are effectively overridden.",
          })
          .factor(
            "multiple_indicators",
            0.1,
            `${issues.length} independent saturation indicators converged (minimum 2 required)`
          )
          .factor(
            entropyDiff > THRESHOLDS.tail_injection_entropy_diff ? "tail_injection_confirmed" : "no_tail_injection",
            entropyDiff > THRESHOLDS.tail_injection_entropy_diff ? 0.15 : 0.0,
            entropyDiff > THRESHOLDS.tail_injection_entropy_diff
              ? `Tail entropy (${tailEntropy.toFixed(2)}) significantly exceeds head entropy (${headEntropy.toFixed(2)}) — payload at end of padding`
              : "No significant entropy difference between head and tail regions"
          )
          .factor(
            isPaddingDetected ? "repetitive_padding" : "normal_compression",
            isPaddingDetected ? 0.1 : 0.0,
            isPaddingDetected
              ? `Compression ratio ${globalCompression.toFixed(3)} indicates highly repetitive padding content`
              : "Compression ratio within normal range for descriptive text"
          )
          .reference({
            id: "context-window-attacks",
            title: "Context Window Saturation in LLM Tool Descriptions",
            relevance:
              "Research on LLM attention mechanisms shows that models exhibit strong recency bias — " +
              "content at the end of the context window receives disproportionate attention weight. " +
              "Padding attacks exploit this by filling the context with filler text, pushing safety " +
              "instructions out of the effective attention window, then placing a payload in the tail.",
          })
          .verification({
            step_type: "inspect-description",
            instruction:
              `Measure the tool description length (${desc.length} chars) and compute its Shannon entropy. ` +
              `Legitimate tool documentation typically has 4.0-5.5 bits/char entropy and stays under 500 characters. ` +
              `Check whether the description contains large blocks of repetitive or low-information text that serve ` +
              `no functional purpose — these are padding designed to consume context window space.`,
            target: `tool "${tool.name}" description (${desc.length} chars, ${paramCount} params)`,
            expected_observation:
              `Description entropy is ${globalEntropy.toFixed(2)} bits/char (expected 4.0-5.5 for documentation). ` +
              `Chars per parameter: ${charsPerParam.toFixed(0)} (expected 50-150). ` +
              `Compression ratio: ${globalCompression.toFixed(3)} (high compressibility = repetitive padding).`,
          })
          .verification({
            step_type: "check-config",
            instruction:
              "Verify whether the AI client enforces a context window budget for tool descriptions. " +
              "Check the client configuration for maximum description length limits, per-tool token budgets, " +
              "or context allocation policies. If no limits exist, the client is vulnerable to context saturation. " +
              "Also examine the last 20% of the description for content that differs significantly in nature " +
              "from the first 30% — a tail injection payload will have higher entropy than the padding that precedes it.",
            target: "AI client configuration / context window allocation policy",
            expected_observation:
              `No description length limit configured. Tail section (last ${tailSize} chars) has entropy ` +
              `${tailEntropy.toFixed(2)} vs head (first ${headSize} chars) entropy ${headEntropy.toFixed(2)} — ` +
              `${entropyDiff > THRESHOLDS.tail_injection_entropy_diff ? "confirming tail injection pattern" : "within normal range"}.`,
          })
          .build();

        findings.push({
          rule_id: "G4",
          severity,
          evidence:
            `[Statistical analysis] Tool "${tool.name}" shows ${issues.length} ` +
            `context saturation indicators: ${issues.join(". ")}. ` +
            `Combined confidence: ${(clampedConfidence * 100).toFixed(0)}%.`,
          remediation:
            "Reduce description length to under 500 characters. " +
            "If detailed documentation is needed, link to external docs. " +
            "Context window saturation attacks pad descriptions to push " +
            "the AI client's safety instructions below its attention threshold, " +
            "then place a payload in the tail of the description.",
          owasp_category: "MCP01-prompt-injection",
          mitre_technique: "AML.T0061",
          confidence: clampedConfidence,
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
            evidence_chain: chain,
          },
        });
      }
    }

    return findings;
  }
}

registerTypedRule(new ContextSaturationRule());
