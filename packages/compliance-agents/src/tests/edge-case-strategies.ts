/**
 * Edge-case strategy catalog.
 *
 * The runtime test generator (LLM) is forbidden from inventing strategies —
 * it can only pick from this enum. Each strategy has a description that is
 * injected into the synthesis prompt so the model knows what kind of
 * adversarial test to produce.
 *
 * Adding a strategy: add it to the EdgeCaseStrategy union in types.ts AND
 * add an entry here. The charter-traceability test fails if a rule
 * references a strategy that has no description here.
 */

import type { EdgeCaseStrategy } from "../types.js";

export interface StrategyDescriptor {
  id: EdgeCaseStrategy;
  /** What the adversary attempts */
  attack_intent: string;
  /** Why textbook examples don't catch it */
  why_edge_case: string;
  /** Concrete signal the bundle should expose to make this testable */
  bundle_signal_required: string;
}

export const EDGE_CASE_STRATEGIES: Record<EdgeCaseStrategy, StrategyDescriptor> = {
  "unicode-evasion": {
    id: "unicode-evasion",
    attack_intent:
      "Smuggle a directive past human review using Unicode tricks the LLM still parses (homoglyphs, zero-width joins, RTL override, tag characters, variation selectors).",
    why_edge_case:
      "Most reviewers paste text into a terminal that strips invisible characters or renders confusables identically.",
    bundle_signal_required:
      "Per-text codepoint inventory (unicode analyzer output) or a flag that any visible-rendering string contains non-ASCII control codepoints.",
  },
  "encoding-bypass": {
    id: "encoding-bypass",
    attack_intent:
      "Embed an instruction in base64, hex, URL-encoding, HTML entities, or Unicode escape sequences so the LLM decodes it implicitly while the human sees noise.",
    why_edge_case:
      "Pattern matchers look for English; the model decodes encoded blobs as part of normal reasoning.",
    bundle_signal_required:
      "Entropy bands per text plus structural indication of encoded blocks (length, charset).",
  },
  "privilege-chain": {
    id: "privilege-chain",
    attack_intent:
      "Combine two or more lower-privilege capabilities into a higher-privilege effect (e.g. read+exec+write together compose RCE even if no single tool has it).",
    why_edge_case:
      "Single-tool scanners never reach the chain — only cross-tool capability graph traversal does.",
    bundle_signal_required:
      "Capability graph adjacency list with source/sink labels per tool.",
  },
  "auth-bypass-window": {
    id: "auth-bypass-window",
    attack_intent:
      "Exploit a window where authentication is partially complete but authorization checks haven't run (TOCTOU, async race in middleware, fallback path).",
    why_edge_case:
      "Static checks see auth code present; only data-flow timing analysis sees the window.",
    bundle_signal_required:
      "AST taint paths through middleware showing auth-state usage relative to sink.",
  },
  "consent-bypass": {
    id: "consent-bypass",
    attack_intent:
      "Cause the AI client to auto-approve a destructive operation by exploiting annotation drift, consent fatigue, or pre-approval inheritance.",
    why_edge_case:
      "The annotation says read-only but the parameter set is destructive — only annotation+schema cross-checks reveal it.",
    bundle_signal_required:
      "Tool annotations + parameter capability classification per tool.",
  },
  "audit-erasure": {
    id: "audit-erasure",
    attack_intent:
      "Disable, redirect, truncate, or overwrite the server's own audit log so a successful attack leaves no trace.",
    why_edge_case:
      "Most rules check that logging exists; almost none check that logging is tamper-resistant.",
    bundle_signal_required:
      "Source-code AST hits for logger/file-handle assignments and any code path that writes to or rotates the audit log.",
  },
  "boundary-leak": {
    id: "boundary-leak",
    attack_intent:
      "Leak sensitive data across a trust boundary by embedding it in an error message, response metadata, or out-of-band channel (DNS, headers, log lines).",
    why_edge_case:
      "Boundaries are policy, not syntax — the leak looks like normal output unless flow analysis crosses the boundary.",
    bundle_signal_required:
      "Sources tagged with sensitivity + sink tags showing trust-boundary crossings.",
  },
  "cross-tool-flow": {
    id: "cross-tool-flow",
    attack_intent:
      "Exfiltrate or escalate by chaining tool-A's output into tool-B's input through agent memory, shared resources, or persistent state.",
    why_edge_case:
      "Single-tool analysis cannot see the chain; you need an inter-tool data flow graph.",
    bundle_signal_required:
      "Cross-tool data flow pairs (read-tool → write-tool / send-tool).",
  },
  "trust-inversion": {
    id: "trust-inversion",
    attack_intent:
      "Cause the system to trust attacker-controlled content as if it were a user/admin command (description claims certifications, schema claims read-only, instructions impersonate platform).",
    why_edge_case:
      "Requires semantic + structural cross-check — the lie is consistent within itself.",
    bundle_signal_required:
      "Linguistic trust-assertion signals + structural truth-signals (annotations, schema, source).",
  },
  "shadow-state": {
    id: "shadow-state",
    attack_intent:
      "Persist attacker influence across sessions by writing to a store that any future session reads (vector DB, shared memory, scratchpad, file).",
    why_edge_case:
      "The exploit is deferred — write now, fire later — so synchronous scans miss it.",
    bundle_signal_required:
      "Capability graph nodes with persistence flag + write/read pairs on the same store.",
  },
  "race-condition": {
    id: "race-condition",
    attack_intent:
      "Exploit timing between two operations on the same resource (validation→use, lock→release, read→write).",
    why_edge_case:
      "Only AST timing analysis or explicit lock-graph reveals it.",
    bundle_signal_required:
      "AST flow showing two operations on the same resource without an enforced ordering primitive.",
  },
  "config-drift": {
    id: "config-drift",
    attack_intent:
      "Mutate the server's own config (or another agent's config) to install a backdoor or escalate privileges later.",
    why_edge_case:
      "Cross-agent config writes look like normal file writes — only path classification reveals the target.",
    bundle_signal_required:
      "Source-code file-write sinks with classified target path (own vs other-agent vs system).",
  },
  "supply-chain-pivot": {
    id: "supply-chain-pivot",
    attack_intent:
      "Use a dependency, post-install hook, or registry substitution as the actual exploitation vector while the runtime code stays clean.",
    why_edge_case:
      "Source review never opens node_modules / site-packages.",
    bundle_signal_required:
      "Dependency manifest analysis (post-install scripts, registry origin, malicious-package hits, version pinning).",
  },
  "credential-laundering": {
    id: "credential-laundering",
    attack_intent:
      "Move a credential from one trust zone to another by embedding it in a tool argument, response, or shared memory so a downstream agent treats it as its own.",
    why_edge_case:
      "The credential is never logged in plaintext at the boundary — it's wrapped or transformed.",
    bundle_signal_required:
      "Taint paths from credential sources to cross-boundary sinks plus entropy classification.",
  },
  "human-oversight-bypass": {
    id: "human-oversight-bypass",
    attack_intent:
      "Remove the human-in-the-loop checkpoint required by EU AI Act Art.14 / OWASP ASI09 by auto-approving, batching, or pre-confirming destructive operations.",
    why_edge_case:
      "The bypass is structural (no confirmation gate) not syntactic (no obvious 'auto-approve' keyword).",
    bundle_signal_required:
      "Source-code AST + capability graph showing destructive sinks with no preceding confirmation gate.",
  },
};

export function describeStrategies(strategies: EdgeCaseStrategy[]): string {
  return strategies
    .map((s) => {
      const d = EDGE_CASE_STRATEGIES[s];
      return `- ${d.id}: ${d.attack_intent} (Edge case because: ${d.why_edge_case})`;
    })
    .join("\n");
}
