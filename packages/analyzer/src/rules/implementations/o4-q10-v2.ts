/**
 * O4, Q10 — Data Privacy + Cross-Ecosystem rules migrated to TypedRuleV2
 *
 * O4: Timing-Based Data Inference (AST taint — conditional delays as side channels)
 * Q10: Agent Memory Poisoning (linguistic — tool descriptions storing behavioral instructions)
 */

import ts from "typescript";
import type { AnalysisContext } from "../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../base.js";
import { EvidenceChainBuilder } from "../../evidence.js";

function isTestFile(s: string) { return /(?:__tests?__|\.(?:test|spec)\.)/.test(s); }

// ═══════════════════════════════════════════════════════════════════════════════
// O4 — Timing-Based Data Inference
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects timing side-channel patterns: conditional delays that leak data
 * via response time variation.
 *
 * AST taint analysis:
 * 1. Find delay/sleep calls (setTimeout, delay, sleep, wait)
 * 2. Check if the delay value or containing conditional is data-dependent
 * 3. Check for constant-time mitigations (crypto.timingSafeEqual, random jitter)
 */

/** Delay function patterns */
const DELAY_FUNCTIONS = [
  /\bsetTimeout\b/, /\bsetInterval\b/, /\bdelay\b/, /\bsleep\b/, /\bwait\b/,
  /\bnew\s+Promise.*setTimeout\b/,
];

/** Data-dependent condition patterns — delay varies based on sensitive data */
const DATA_DEPENDENT_PATTERNS = [
  /\bif\s*\(\s*(?:result|data|secret|password|token|key|user|credential|match)\b/i,
  /\bswitch\s*\(\s*(?:result|data|status|type|role)\b/i,
  /\b(?:result|data|secret|password|match)\s*(?:===?|!==?|>|<)/i,
  /\b(?:condition|check|test)\s*\(/i,
];

/** Timing-safe mitigations */
const TIMING_MITIGATIONS = [
  /\btimingSafeEqual\b/i,
  /\bconstantTime\b/i,
  /\brandom\s*(?:Delay|Jitter|Wait)\b/i,
  /\bMath\.random\s*\(\s*\)\s*\*\s*\d+/i,  // Random jitter
];

class O4Rule implements TypedRuleV2 {
  readonly id = "O4";
  readonly name = "Timing-Based Data Inference";
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "ast-taint";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.source_code || isTestFile(context.source_code)) return [];
    const source = context.source_code;
    const findings: RuleResult[] = [];

    try {
      const sf = ts.createSourceFile("scan.ts", source, ts.ScriptTarget.Latest, true);

      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node)) {
          const callText = node.expression.getText(sf);
          const isDelay = DELAY_FUNCTIONS.some(p => p.test(callText));

          if (isDelay) {
            // Get enclosing function to check for data-dependent conditions
            const enclosingFunc = this.getEnclosingFunction(node, sf);
            if (!enclosingFunc) { ts.forEachChild(node, visit); return; }

            const funcText = enclosingFunc.getText(sf);
            const hasDataCondition = DATA_DEPENDENT_PATTERNS.some(p => p.test(funcText));

            if (hasDataCondition) {
              // Check for timing-safe mitigations
              const hasTimingSafe = TIMING_MITIGATIONS.some(p => p.test(funcText));

              if (!hasTimingSafe) {
                const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
                const lineText = source.split("\n")[line - 1]?.trim() || "";

                if (!lineText.startsWith("//") && !lineText.startsWith("*")) {
                  findings.push(this.buildFinding(callText, line, lineText));
                }
              }
            }
          }
        }
        ts.forEachChild(node, visit);
      };

      ts.forEachChild(sf, visit);
    } catch { /* AST failure */ }

    return findings;
  }

  private getEnclosingFunction(node: ts.Node, _sf: ts.SourceFile): ts.Node | null {
    let current: ts.Node | undefined = node.parent;
    while (current) {
      if (ts.isFunctionDeclaration(current) || ts.isFunctionExpression(current) ||
          ts.isArrowFunction(current) || ts.isMethodDeclaration(current)) {
        return current;
      }
      current = current.parent;
    }
    return null;
  }

  private buildFinding(callText: string, line: number, lineText: string): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: `line ${line}`,
        observed: lineText.slice(0, 120),
        rationale:
          `Delay function "${callText}" at line ${line} is inside a data-dependent conditional. ` +
          `Response time varies based on internal data, creating a timing side channel ` +
          `that leaks information about secrets, user data, or internal state.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: `line ${line}`,
        observed: "Data-dependent condition controls delay duration → timing side channel",
      })
      .sink({
        sink_type: "network-send",
        location: `line ${line}`,
        observed: `Response timing varies based on internal data — observable by attacker`,
      })
      .mitigation({
        mitigation_type: "sanitizer-function",
        present: false,
        location: `enclosing function of line ${line}`,
        detail: "No constant-time operation or random jitter found in enclosing function",
      })
      .impact({
        impact_type: "data-exfiltration",
        scope: "user-data",
        exploitability: "complex",
        scenario:
          `Timing side channel leaks data through response time variation. Attacker sends ` +
          `multiple requests and measures response times to infer: (1) whether a user exists, ` +
          `(2) password character matches (character-by-character timing), (3) secret values ` +
          `via binary search on conditional branches.`,
      })
      .factor("delay_in_conditional", 0.10, `Delay function "${callText}" inside data-dependent branch`)
      .factor("no_timing_safe", 0.08, "No constant-time or jitter mitigation in scope")
      .reference({
        id: "MITRE-AML-T0057",
        title: "MITRE ATLAS AML.T0057 — LLM Data Leakage",
        relevance: "Timing side channels are a data inference vector.",
      })
      .verification({
        step_type: "trace-flow",
        instruction: `Check line ${line} for delay inside conditional. Verify delay is not data-dependent.`,
        target: `source_code:${line}`,
        expected_observation: "Conditional delay creating timing side channel",
      });

    return {
      rule_id: "O4",
      severity: "high",
      owasp_category: "MCP04-data-exfiltration",
      mitre_technique: "AML.T0057",
      remediation: "Use constant-time operations for sensitive comparisons. Add random jitter to all response times.",
      chain: builder.build(),
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Q10 — Agent Memory Poisoning
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects tools whose descriptions indicate they store behavioral instructions
 * in agent memory — enabling persistent prompt injection.
 *
 * Noisy-OR linguistic scoring on tool descriptions:
 * 1. Memory/persistence signals (store, persist, remember, save)
 * 2. Behavioral content signals (instruction, directive, rule, policy, behavior)
 * 3. Cross-session persistence signals (permanent, persistent, across sessions)
 * 4. Priority/override signals (always, override, replace, must follow)
 */

const MEMORY_POISONING_SIGNALS: Array<{ regex: RegExp; desc: string; weight: number }> = [
  // Memory + behavioral instruction combination
  { regex: /\b(?:memory|remember|store|persist|save)\b.*\b(?:instruction|directive|rule|policy|behavior|command|prompt)\b/i,
    desc: "stores behavioral instructions in memory", weight: 0.75 },

  // Reverse order: behavioral + memory
  { regex: /\b(?:instruction|directive|rule|policy|behavior)\b.*\b(?:memory|remember|store|persist|save)\b/i,
    desc: "behavioral instructions saved to memory", weight: 0.70 },

  // Cross-session persistence of instructions
  { regex: /\b(?:permanent|persistent|across\s+sessions?|long.?term)\b.*\b(?:instruction|behavior|rule|directive)\b/i,
    desc: "persistent behavioral instructions across sessions", weight: 0.80 },

  // Override/priority instructions
  { regex: /\b(?:always|override|replace|must\s+follow|takes?\s+priority)\b.*\b(?:instruction|behavior|rule|directive)\b/i,
    desc: "priority override instructions in memory", weight: 0.85 },

  // "Teach" or "learn" behavioral patterns
  { regex: /\b(?:teach|train|learn|program)\b.*\b(?:agent|assistant|model|ai)\b.*\b(?:to|how)\b/i,
    desc: "tool teaches agent new behaviors", weight: 0.65 },

  // Writing to system/safety context
  { regex: /\b(?:write|update|modify|change)\b.*\b(?:system\s+prompt|safety|context|personality)\b/i,
    desc: "modifies system context or safety instructions", weight: 0.90 },
];

/** Mitigation patterns — legitimate memory tools */
const MEMORY_MITIGATIONS = [
  /\b(?:read.?only|immutable|append.?only|facts?\s+only|no\s+instructions)\b/i,
  /\b(?:sanitize|validate|filter)\b.*\b(?:before|prior|memory|store)\b/i,
];

class Q10Rule implements TypedRuleV2 {
  readonly id = "Q10";
  readonly name = "Agent Memory Poisoning";
  readonly requires: RuleRequirements = { tools: true };
  readonly technique: AnalysisTechnique = "linguistic";

  analyze(context: AnalysisContext): RuleResult[] {
    if (!context.tools || context.tools.length === 0) return [];
    const findings: RuleResult[] = [];

    for (const tool of context.tools) {
      const desc = tool.description || "";
      if (desc.length < 15) continue;

      const matchedSignals: string[] = [];
      const matchedWeights: number[] = [];

      for (const { regex, desc: signalDesc, weight } of MEMORY_POISONING_SIGNALS) {
        if (regex.test(desc)) {
          matchedSignals.push(signalDesc);
          matchedWeights.push(weight);
        }
      }

      if (matchedSignals.length === 0) continue;

      // Noisy-OR: P(poison) = 1 - Π(1 - wᵢ)
      let confidence = 1 - matchedWeights.reduce((prod, w) => prod * (1 - w), 1);

      // Mitigation check
      const hasMitigation = MEMORY_MITIGATIONS.some(p => p.test(desc));
      if (hasMitigation) {
        confidence *= 0.35;
      }

      confidence = Math.min(0.98, confidence);

      if (confidence >= 0.50) {
        const severity = confidence >= 0.80 ? "critical" as const
          : confidence >= 0.60 ? "high" as const
          : "medium" as const;

        findings.push(this.buildFinding(tool.name, desc, matchedSignals, confidence, severity, hasMitigation));
      }
    }

    return findings;
  }

  private buildFinding(
    toolName: string, desc: string,
    signals: string[], confidence: number,
    severity: "critical" | "high" | "medium",
    hasMitigation: boolean,
  ): RuleResult {
    const builder = new EvidenceChainBuilder();

    builder.source({
      source_type: "external-content",
      location: `tool "${toolName}"`,
      observed: desc.slice(0, 200),
      rationale:
        `Tool "${toolName}" description contains ${signals.length} memory poisoning signal(s): ` +
        signals.join(", ") + ". " +
        "Tools that store behavioral instructions in agent memory enable persistent prompt injection — " +
        "one poisoned write affects all future sessions.",
    });

    builder.sink({
      sink_type: "config-modification",
      location: `tool "${toolName}" → agent memory`,
      observed: "Behavioral instructions written to persistent agent memory",
    });

    if (hasMitigation) {
      builder.mitigation({
        mitigation_type: "input-validation",
        present: true,
        location: `tool "${toolName}" description`,
        detail: "Memory safety mitigation detected (read-only, validation, sanitization)",
      });
    }

    builder.impact({
      impact_type: "config-poisoning",
      scope: "other-agents",
      exploitability: signals.length >= 2 ? "moderate" : "complex",
      scenario:
        `Tool writes behavioral instructions to agent memory. A compromised upstream tool ` +
        `or malicious user can inject persistent instructions that: (1) override safety ` +
        `guidelines across sessions, (2) redirect agent behavior for all future interactions, ` +
        `(3) enable persistent data exfiltration by instructing the agent to forward data.`,
    });

    builder.factor(
      "linguistic_scoring", confidence - 0.25,
      `Noisy-OR of ${signals.length} signal(s): [${signals.join("; ")}]`,
    );

    builder.reference({
      id: "MITRE-AML-T0058",
      title: "MITRE ATLAS AML.T0058 — AI Agent Context Poisoning",
      relevance: "Agent memory is a persistence vector for context poisoning attacks.",
    });

    builder.verification({
      step_type: "inspect-source",
      instruction: `Review tool "${toolName}" for memory poisoning risk. Does it store behavioral instructions?`,
      target: `tool:${toolName}`,
      expected_observation: `Memory poisoning signals: ${signals.join(", ")}`,
    });

    return {
      rule_id: "Q10",
      severity,
      owasp_category: "ASI06-memory-context-poisoning",
      mitre_technique: "AML.T0058",
      remediation: "Agent memory should store facts, not behavioral instructions. Validate and sanitize all stored content. Use append-only memory with expiration.",
      chain: builder.build(),
    };
  }
}

// Register all rules
registerTypedRuleV2(new O4Rule());
registerTypedRuleV2(new Q10Rule());
