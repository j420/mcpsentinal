/**
 * K16 — Unbounded Recursion / Missing Depth Limits (v2).
 *
 * Emits one finding per recursion cycle (direct, mutual, MCP tool-call,
 * or emitter-dispatch) whose entry function lacks both a depth-comparison
 * guard and a visited-set cycle breaker. Zero regex. Confidence cap 0.88
 * (runtime-only guards — V8 stack size, MCP client tool-call-depth limits,
 * external circuit breakers — are invisible to static analysis).
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder, type EvidenceChain } from "../../../evidence.js";
import { gatherK16, type K16Gathered, type RecursionCycle } from "./gather.js";
import {
  stepInspectCall,
  stepInspectEntry,
  stepInspectCycleBreaker,
} from "./verification.js";

const RULE_ID = "K16";
const RULE_NAME = "Unbounded Recursion / Missing Depth Limits";
const OWASP = "MCP07-insecure-config" as const;
const MITRE: string | null = null;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Every recursive handler must carry an explicit termination budget. " +
  "For tree / DAG walks, thread a `depth` parameter with a comparison " +
  "against an UPPER_SNAKE constant: `if (depth > MAX_DEPTH) return;`. " +
  "For graphs with cycles, use a visited-set (`new Set()` / `new WeakSet()`) " +
  "consulted with `.has()` before recursing and updated with `.add()` on " +
  "entry. For MCP tool-call roundtrips (recursionA→callTool('B')→callTool('A')), " +
  "pair the per-function guard with a session-level tool-call-depth counter " +
  "carried through the tool arguments; the MCP spec does not enforce this " +
  "client-side. OWASP ASI08 and EU AI Act Art.15 both require robustness " +
  "against adversarial input-driven recursion.";

const REF_OWASP_ASI08 = {
  id: "OWASP-ASI08",
  title: "OWASP Agentic Security Initiative — ASI08: Denial of Service",
  url: "https://owasp.org/www-project-agentic-security-initiative/",
  relevance:
    "ASI08 names unguarded recursion as an archetypal cascading-failure " +
    "enabler in agentic systems. An MCP tool handler that recurses — directly, " +
    "mutually, or via a tool-call roundtrip — without a termination budget " +
    "lets an adversarial client drive the handler to a stack overflow, RSS " +
    "blow-out, or tool-call storm.",
} as const;

class UnboundedRecursionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK16(context);
    const findings: RuleResult[] = [];
    for (const file of gathered.perFile) {
      if (file.isTestFile) continue;
      for (const cycle of file.cycles) {
        findings.push(this.buildFinding(cycle, gathered));
      }
    }
    return findings.slice(0, 10);
  }

  private buildFinding(cycle: RecursionCycle, gathered: K16Gathered): RuleResult {
    const cycleDescription = describeCycle(cycle);
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: cycle.callLocation,
        observed: cycle.observedCall,
        rationale:
          `Recursive call closing a cycle with entry \`${cycle.entryLabel}\`: ` +
          `${cycleDescription}. The entry function declares no depth-comparison ` +
          `guard (BinaryExpression vs numeric literal / UPPER_SNAKE constant) and ` +
          `no visited-set cycle breaker (Set / Map / WeakSet with .has/.add). ` +
          `Adversarial input or an adversarial tool-call sequence deterministically ` +
          `drives the recursion to its runtime limit.`,
      })
      .propagation({
        propagation_type: "function-call",
        location: cycle.callLocation,
        observed:
          `Call-graph edge of kind \`${cycle.edgeKind}\` re-enters the cycle ` +
          `{${cycle.cycleMembers.join(" → ")}} from \`${cycle.entryLabel}\`. ` +
          `Each iteration pushes a new activation record onto the JavaScript ` +
          `call stack (or consumes a fresh MCP tool-call slot for the ` +
          `tool-call-roundtrip variant).`,
      })
      .sink({
        sink_type: "code-evaluation",
        location: cycle.entryLocation,
        observed:
          `Entry function \`${cycle.entryLabel}\` is the cycle's header and the ` +
          `point at which an unbounded activation-record chain or an unbounded ` +
          `tool-call sequence materialises.`,
      })
      .mitigation({
        mitigation_type: "rate-limit",
        present: false,
        location: cycle.entryLocation,
        detail:
          `No depth-comparison guard and no visited-set cycle breaker in ` +
          `\`${cycle.entryLabel}\`. ` +
          (cycle.hasDepthParameter
            ? `(A parameter in the depth-name vocabulary IS declared, but the ` +
              `function body does not compare it against an upper bound — per ` +
              `charter, the parameter name alone is not a guard.)`
            : `(No parameter in the depth-name vocabulary declared.)`),
      })
      .impact({
        impact_type: "denial-of-service",
        scope: cycle.edgeKind === "tool-call-roundtrip" ? "other-agents" : "server-host",
        exploitability: "trivial",
        scenario: buildScenario(cycle),
      });

    builder.factor(
      "recursion_edge_without_guard",
      0.12,
      `AST call-graph SCC analysis confirmed the cycle edge \`${cycle.edgeKind}\` ` +
        `into \`${cycle.entryLabel}\` and the entry function has no depth ` +
        `comparison and no visited-set cycle breaker.`,
    );

    if (!cycle.hasDepthParameter) {
      builder.factor(
        "no_depth_parameter",
        0.06,
        `Entry function declares no parameter in the depth-name vocabulary — ` +
          `the absence is structurally total, not partial.`,
      );
    } else {
      builder.factor(
        "no_depth_comparison",
        0.04,
        `Entry function declares a depth-name parameter but no comparison ` +
          `against a numeric literal or UPPER_SNAKE constant — the guard is ` +
          `vacuous.`,
      );
    }

    builder.factor(
      "no_cycle_breaker",
      0.04,
      `Entry function body contains no visited-set pattern ` +
        `(new Set()/Map()/WeakSet() + .has/.add).`,
    );

    if (cycle.edgeKind === "tool-call-roundtrip") {
      builder.factor(
        "tool_call_cycle_synthesised",
        0.06,
        `Cycle closes via an MCP tool-call synthetic edge — the protocol layer ` +
          `amplifies the DoS by routing each recursion through a full tool-call ` +
          `request/response roundtrip.`,
      );
    } else if (cycle.edgeKind === "mutual-recursion") {
      builder.factor(
        "mutual_recursion_scc",
        0.03,
        `Cycle has ≥2 nodes — the SCC closes via mutual recursion, which a ` +
          `per-function self-call scan misses.`,
      );
    }

    builder.reference(REF_OWASP_ASI08);
    builder.verification(stepInspectCall(cycle));
    builder.verification(stepInspectEntry(cycle));
    builder.verification(stepInspectCycleBreaker(cycle));

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

    // Silence: K16Gathered is passed through in case future factors need
    // aggregate file-level context (e.g. multiple cycles in the same file).
    void gathered;

    return {
      rule_id: RULE_ID,
      severity: "high",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function describeCycle(cycle: RecursionCycle): string {
  if (cycle.cycleMembers.length === 1) {
    return `direct self-recursion on \`${cycle.entryLabel}\``;
  }
  return `multi-node recursion cycle {${cycle.cycleMembers.join(" → ")}}`;
}

function buildScenario(cycle: RecursionCycle): string {
  const common =
    `An adversarial input or tool-call sequence drives the cycle to its ` +
    `runtime limit. `;
  switch (cycle.edgeKind) {
    case "direct-self-call":
      return (
        common +
        `Direct self-call on \`${cycle.entryLabel}\`: a deep data structure ` +
        `(e.g. a JSON object with 10 000 nested children) exhausts the V8 ` +
        `call stack within milliseconds, throws RangeError, and terminates ` +
        `the handler. The MCP server process may remain alive but the ` +
        `tool-call worker is lost; under concurrent load the server sheds ` +
        `legitimate traffic.`
      );
    case "mutual-recursion":
      return (
        common +
        `Mutual recursion across {${cycle.cycleMembers.join(" → ")}}: a ` +
        `per-function self-call scan does not see the cycle, which is ` +
        `precisely why attackers target this shape. Same stack-exhaustion ` +
        `outcome as direct recursion.`
      );
    case "tool-call-roundtrip":
      return (
        common +
        `Tool-call roundtrip across {${cycle.cycleMembers.join(" → ")}}: each ` +
        `iteration consumes a full MCP request/response pair. On a common ` +
        `MCP client (Claude Desktop, Cursor) each roundtrip serialises JSON, ` +
        `enters the model's reasoning loop, and emits the next tool-call. ` +
        `With 500+ roundtrips the client-side session budget is exhausted ` +
        `and the agent's other work is starved. OWASP ASI08 names this as ` +
        `the archetype of the "cascading failure" category.`
      );
    case "emit-roundtrip":
      return (
        common +
        `Emitter/dispatcher roundtrip across {${cycle.cycleMembers.join(" → ")}}: ` +
        `the function emits an event whose listener re-enters the function. ` +
        `Without a visited-set or a depth counter, one external emit() ` +
        `triggers an unbounded event storm; the process' microtask queue ` +
        `saturates and unrelated handlers starve.`
      );
  }
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K16 charter caps confidence at ${cap} — the scanner cannot observe ` +
      `V8 --stack-size overrides, MCP client-side per-session tool-call-depth ` +
      `enforcement (Anthropic Desktop / Cursor / Claude Code each implement ` +
      `this differently and none expose it via protocol metadata), or ` +
      `external circuit-breaker wrappers (opossum / cockatiel). A ` +
      `maximum-confidence claim would overstate what static analysis can prove.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new UnboundedRecursionRule());

export { UnboundedRecursionRule };
