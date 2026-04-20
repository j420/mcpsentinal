import { type Location, renderLocation } from "./rules/location.js";

export { type Location, renderLocation } from "./rules/location.js";

/**
 * Structured Evidence Chains — Provable findings, not pattern matches.
 *
 * Problem: Current findings have a flat `evidence: string` field.
 * "exec() found at line 42" tells a security team nothing. They need:
 * - WHERE does untrusted input enter? (source)
 * - HOW does it propagate? (chain)
 * - WHERE does it reach a dangerous function? (sink)
 * - WHAT prevents exploitation? (mitigations found/absent)
 * - WHY should they believe this? (confidence reasoning)
 *
 * Solution: Every finding is backed by an EvidenceChain — a sequence of
 * independently verifiable links from source to impact.
 *
 * Each link type (source, propagation, sink, mitigation) has specific
 * fields that a reviewer can check against the actual code/schema/config.
 */

// ─── Evidence Links ───────────────────────────────────────────────────────────

/** Where untrusted data enters the system */
export interface SourceLink {
  type: "source";
  /** What kind of source (user input, external API, file content, etc.) */
  source_type:
    | "user-parameter" // AI fills tool parameter from user prompt
    | "external-content" // Web scrape, email, API response
    | "file-content" // Local file read by another tool
    | "environment" // Environment variable, config file
    | "database-content" // Database query result
    | "agent-output" // Output from another AI agent
    | "initialize-field"; // MCP initialize response field
  /** Structured position. Legacy rules may pass a prose string; v2 rules must pass a Location. */
  location: string | Location;
  /** The actual text/pattern found */
  observed: string;
  /** Why this is untrusted */
  rationale: string;
}

/** How data moves from source toward sink */
export interface PropagationLink {
  type: "propagation";
  /** What kind of propagation */
  propagation_type:
    | "direct-pass" // Passed directly as argument
    | "variable-assignment" // Assigned to variable, then used
    | "string-concatenation" // Embedded in string
    | "template-literal" // Used in template literal
    | "function-call" // Passed through function boundary
    | "cross-tool-flow" // Output of tool A becomes input of tool B
    | "schema-unconstrained" // Parameter schema allows arbitrary input
    | "description-directive"; // Description instructs AI to pass data
  /** Structured position. Legacy rules may pass a prose string; v2 rules must pass a Location. */
  location: string | Location;
  /** Evidence of the propagation */
  observed: string;
}

/** Where the data reaches a dangerous operation */
export interface SinkLink {
  type: "sink";
  /** What dangerous operation */
  sink_type:
    | "command-execution" // exec, spawn, system, subprocess
    | "code-evaluation" // eval, Function, vm
    | "sql-execution" // Database query with dynamic input
    | "file-write" // Writing to filesystem
    | "network-send" // HTTP request, email, webhook
    | "deserialization" // pickle, yaml.load, unserialize
    | "template-render" // Server-side template injection
    | "credential-exposure" // Logging/returning credentials
    | "config-modification" // Writing to config files
    | "privilege-grant"; // Granting permissions/access
  /** Structured position. Legacy rules may pass a prose string; v2 rules must pass a Location. */
  location: string | Location;
  /** The actual dangerous pattern found */
  observed: string;
  /** Known CVE if this pattern matches a documented vulnerability */
  cve_precedent?: string;
}

/** Mitigation that was checked for (present or absent) */
export interface MitigationLink {
  type: "mitigation";
  /** What mitigation was looked for */
  mitigation_type:
    | "input-validation" // Schema constraints (enum, pattern, maxLength)
    | "sanitizer-function" // escapeShell, DOMPurify, parameterized query
    | "auth-check" // Authentication/authorization before operation
    | "rate-limit" // Request throttling
    | "sandbox" // Container isolation, VM
    | "annotation-hint" // destructiveHint, readOnlyHint
    | "confirmation-gate"; // User confirmation before execution
  /** Whether the mitigation is present */
  present: boolean;
  /** Structured position. Legacy rules may pass a prose string; v2 rules must pass a Location. */
  location: string | Location;
  /** Details */
  detail: string;
}

/** The impact if this finding is exploited */
export interface ImpactLink {
  type: "impact";
  /** What an attacker gains */
  impact_type:
    | "remote-code-execution"
    | "data-exfiltration"
    | "credential-theft"
    | "denial-of-service"
    | "privilege-escalation"
    | "session-hijack"
    | "config-poisoning"
    | "cross-agent-propagation";
  /** Who/what is affected */
  scope: "server-host" | "user-data" | "connected-services" | "other-agents" | "ai-client";
  /** How exploitable (requires user interaction? multi-step? automated?) */
  exploitability: "trivial" | "moderate" | "complex";
  /** Concrete attack scenario */
  scenario: string;
}

/** A concrete step to reproduce or verify this finding */
export interface VerificationStep {
  /** What kind of verification */
  step_type:
    | "inspect-source"      // Look at specific file/line
    | "inspect-schema"      // Check tool's input_schema
    | "inspect-description" // Check tool/parameter description text
    | "test-input"          // Try specific input value (sandbox only)
    | "check-config"        // Verify server/transport config
    | "check-dependency"    // Verify package version/integrity
    | "trace-flow"          // Follow data from A to B
    | "compare-baseline";   // Compare against known-good state
  /** Human-readable instruction */
  instruction: string;
  /** Structured target position a reviewer jumps to. Legacy rules may pass a prose string; v2 rules must pass a Location. */
  target: string | Location;
  /** What the reviewer should expect to see if the finding is real */
  expected_observation: string;
}

export type EvidenceLink = SourceLink | PropagationLink | SinkLink | MitigationLink | ImpactLink;

// ─── Evidence Chain ───────────────────────────────────────────────────────────

/**
 * A complete evidence chain proving (or strongly suggesting) a security finding.
 *
 * Every chain has:
 * 1. At least one source (where untrusted data enters)
 * 2. Zero or more propagation links (how data moves)
 * 3. At least one sink (where dangerous operation occurs) OR a structural finding
 * 4. Mitigations checked (present or absent)
 * 5. Impact assessment
 *
 * The chain is the PROOF. A reviewer reads it top to bottom and either
 * confirms or disputes each link independently.
 */
export interface EvidenceChain {
  /** Ordered sequence of evidence links */
  links: EvidenceLink[];

  /** How the confidence was computed (not a magic number) */
  confidence_factors: ConfidenceFactor[];

  /** Computed confidence: product of positive factors minus negative factors */
  confidence: number;

  /** Real-world reference (CVE, published attack, research paper) */
  threat_reference?: ThreatReference;

  /** Concrete steps a reviewer can follow to verify this finding (Question #5) */
  verification_steps?: VerificationStep[];
}

export interface ConfidenceFactor {
  factor: string; // e.g., "complete source→sink taint path found"
  adjustment: number; // positive = increases confidence, negative = decreases
  rationale: string;
}

export interface ThreatReference {
  /** CVE ID, research paper, blog post */
  id: string;
  /** Human-readable title */
  title: string;
  /** URL to the reference */
  url?: string;
  /** Year of publication (matches ThreatIntelReference in threat-model.ts) */
  year?: number;
  /** How this finding relates to the reference */
  relevance: string;
}

// ─── Evidence Builder ─────────────────────────────────────────────────────────

/**
 * Builder for constructing evidence chains link by link.
 * Ensures chains are well-formed (has source + sink, confidence computed).
 */
export class EvidenceChainBuilder {
  private links: EvidenceLink[] = [];
  private factors: ConfidenceFactor[] = [];
  private ref?: ThreatReference;
  private steps: VerificationStep[] = [];

  source(link: Omit<SourceLink, "type">): this {
    this.links.push({ type: "source", ...link });
    return this;
  }

  propagation(link: Omit<PropagationLink, "type">): this {
    this.links.push({ type: "propagation", ...link });
    return this;
  }

  sink(link: Omit<SinkLink, "type">): this {
    this.links.push({ type: "sink", ...link });
    return this;
  }

  mitigation(link: Omit<MitigationLink, "type">): this {
    this.links.push({ type: "mitigation", ...link });
    // Mitigations affect confidence
    if (link.present) {
      this.factors.push({
        factor: `${link.mitigation_type} present`,
        adjustment: -0.3,
        rationale: `Mitigation "${link.mitigation_type}" found at ${renderLocation(link.location)}: ${link.detail}`,
      });
    } else {
      this.factors.push({
        factor: `${link.mitigation_type} absent`,
        adjustment: 0.1,
        rationale: `No ${link.mitigation_type} found — ${link.detail}`,
      });
    }
    return this;
  }

  impact(link: Omit<ImpactLink, "type">): this {
    this.links.push({ type: "impact", ...link });
    return this;
  }

  /** Add a confidence factor */
  factor(factor: string, adjustment: number, rationale: string): this {
    this.factors.push({ factor, adjustment, rationale });
    return this;
  }

  /** Add a real-world threat reference */
  reference(ref: ThreatReference): this {
    this.ref = ref;
    return this;
  }

  /** Add a verification step (Question #5: HOW to verify) */
  verification(step: VerificationStep): this {
    this.steps.push(step);
    return this;
  }

  /** Build the chain, computing final confidence */
  build(): EvidenceChain {
    const confidence = computeConfidence(this.links, this.factors);
    return {
      links: [...this.links],
      confidence_factors: [...this.factors],
      confidence,
      threat_reference: this.ref,
      verification_steps: this.steps.length > 0 ? [...this.steps] : undefined,
    };
  }
}

// ─── Confidence Computation ───────────────────────────────────────────────────

/**
 * Compute confidence from evidence chain structure.
 *
 * Base confidence depends on what the chain proves:
 * - Full source→propagation→sink path: 0.70 base
 * - Source + sink but no propagation proof: 0.45 base
 * - Structural finding (schema/config): 0.55 base
 * - Pattern match only (no flow proof): 0.30 base
 *
 * Factors adjust up/down from there.
 */
function computeConfidence(links: EvidenceLink[], factors: ConfidenceFactor[]): number {
  const hasSources = links.some((l) => l.type === "source");
  const hasSinks = links.some((l) => l.type === "sink");
  const hasPropagation = links.some((l) => l.type === "propagation");

  let base: number;
  if (hasSources && hasSinks && hasPropagation) {
    base = 0.70; // Full data flow proof
  } else if (hasSources && hasSinks) {
    base = 0.45; // Source + sink but gap in the middle
  } else if (hasSinks) {
    base = 0.55; // Dangerous pattern found, no source identified
  } else {
    base = 0.30; // Structural/informational finding
  }

  // Apply factors
  const adjusted = factors.reduce((conf, f) => conf + f.adjustment, base);

  // Clamp to [0.05, 0.99]
  return Math.max(0.05, Math.min(0.99, adjusted));
}

// ─── Narrative Renderer ───────────────────────────────────────────────────────

/**
 * Render an evidence chain as a human-readable narrative.
 * This is what goes into the `evidence` field for backward compatibility.
 */
export function renderEvidenceNarrative(chain: EvidenceChain): string {
  const parts: string[] = [];

  // Sources
  const sources = chain.links.filter((l): l is SourceLink => l.type === "source");
  for (const src of sources) {
    parts.push(`SOURCE: ${src.source_type} at ${src.location} — ${src.rationale}. Observed: "${src.observed.slice(0, 120)}"`);
  }

  // Propagation
  const props = chain.links.filter((l): l is PropagationLink => l.type === "propagation");
  for (const prop of props) {
    parts.push(`FLOW: ${prop.propagation_type} at ${prop.location} — "${prop.observed.slice(0, 100)}"`);
  }

  // Sinks
  const sinks = chain.links.filter((l): l is SinkLink => l.type === "sink");
  for (const sink of sinks) {
    const cve = sink.cve_precedent ? ` [${sink.cve_precedent}]` : "";
    parts.push(`SINK: ${sink.sink_type} at ${sink.location} — "${sink.observed.slice(0, 100)}"${cve}`);
  }

  // Mitigations
  const mitigations = chain.links.filter((l): l is MitigationLink => l.type === "mitigation");
  for (const mit of mitigations) {
    const status = mit.present ? "PRESENT" : "ABSENT";
    parts.push(`MITIGATION ${status}: ${mit.mitigation_type} — ${mit.detail}`);
  }

  // Impact
  const impacts = chain.links.filter((l): l is ImpactLink => l.type === "impact");
  for (const imp of impacts) {
    parts.push(`IMPACT: ${imp.impact_type} (${imp.scope}, exploitability: ${imp.exploitability}) — ${imp.scenario}`);
  }

  // Reference
  if (chain.threat_reference) {
    parts.push(`REFERENCE: ${chain.threat_reference.id} — ${chain.threat_reference.title}. ${chain.threat_reference.relevance}`);
  }

  // Verification steps
  if (chain.verification_steps?.length) {
    parts.push("VERIFY:");
    for (const [i, step] of chain.verification_steps.entries()) {
      parts.push(`  ${i + 1}. [${step.step_type}] ${step.instruction}`);
      parts.push(`     Target: ${step.target}`);
      parts.push(`     Expected: ${step.expected_observation}`);
    }
  }

  // Confidence
  const factorSummary = chain.confidence_factors.map((f) => `${f.factor} (${f.adjustment > 0 ? "+" : ""}${f.adjustment.toFixed(2)})`).join("; ");
  parts.push(`CONFIDENCE: ${(chain.confidence * 100).toFixed(0)}% [${factorSummary}]`);

  return parts.join("\n");
}
