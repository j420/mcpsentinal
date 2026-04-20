/**
 * Shared test utilities for evidence chain validation.
 *
 * Every upgraded test uses these helpers to assert that findings produce
 * well-structured, auditable evidence chains — not just "pattern matched".
 *
 * The assertions here map directly to what compliance frameworks require:
 * - EU AI Act Art. 12: Auditable evidence trails
 * - ISO 27001 A.8.15: Logging adequacy
 * - ISO 42001 A.8.1: Transparency in AI system assessments
 */

import { expect } from "vitest";
import type { AnalysisContext } from "../src/engine.js";
import type { TypedFinding } from "../src/rules/base.js";
import type { EvidenceChain, EvidenceLink, SourceLink, SinkLink } from "../src/evidence.js";
import { renderLocation } from "../src/rules/location.js";

// ─── Context Factory ─────────────────────────────────────────────────────────

/** Create a minimal AnalysisContext with sensible defaults */
export function makeCtx(overrides: Partial<AnalysisContext> = {}): AnalysisContext {
  return {
    server: { id: "test-server", name: "test", description: null, github_url: null },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    ...overrides,
  };
}

// ─── Finding Extraction ──────────────────────────────────────────────────────

/** Extract the first finding for a specific rule ID, or fail with a clear message */
export function findingFor(findings: TypedFinding[], ruleId: string): TypedFinding {
  const f = findings.find((x) => x.rule_id === ruleId);
  if (!f) {
    const found = findings.map((x) => x.rule_id).join(", ") || "(none)";
    throw new Error(`Expected finding for ${ruleId} but got: [${found}]`);
  }
  return f;
}

/** Extract the evidence chain from a finding, or fail with a clear message */
export function chainFor(finding: TypedFinding): EvidenceChain {
  const chain = finding.metadata?.evidence_chain as EvidenceChain | undefined;
  if (!chain) {
    throw new Error(
      `Finding ${finding.rule_id} has no evidence_chain in metadata. ` +
      `Evidence text: "${finding.evidence?.slice(0, 100)}..."`,
    );
  }
  return chain;
}

// ─── Evidence Chain Assertions ───────────────────────────────────────────────

/**
 * Assert that a finding has a well-formed evidence chain with the minimum
 * structure required for compliance reporting.
 *
 * This is the CORE assertion — every upgraded test calls this.
 */
export function expectEvidenceChain(finding: TypedFinding): EvidenceChain {
  // Chain must exist
  const chain = chainFor(finding);

  // Must have links array
  expect(chain.links).toBeDefined();
  expect(Array.isArray(chain.links)).toBe(true);
  expect(chain.links.length).toBeGreaterThanOrEqual(1);

  // Must have at least one source OR one sink (structural findings may only have sink)
  const sources = chain.links.filter((l: EvidenceLink) => l.type === "source");
  const sinks = chain.links.filter((l: EvidenceLink) => l.type === "sink");
  expect(
    sources.length > 0 || sinks.length > 0,
  ).toBe(true);

  // Confidence must be computed (not zero, not undefined)
  expect(chain.confidence).toBeDefined();
  expect(typeof chain.confidence).toBe("number");
  expect(chain.confidence).toBeGreaterThanOrEqual(0.05);
  expect(chain.confidence).toBeLessThanOrEqual(0.99);

  // Confidence factors must explain the score
  expect(chain.confidence_factors).toBeDefined();
  expect(Array.isArray(chain.confidence_factors)).toBe(true);
  expect(chain.confidence_factors.length).toBeGreaterThanOrEqual(1);

  // Each factor must have the required fields
  for (const factor of chain.confidence_factors) {
    expect(factor.factor).toBeDefined();
    expect(typeof factor.factor).toBe("string");
    expect(factor.factor.length).toBeGreaterThan(0);
    expect(typeof factor.adjustment).toBe("number");
    expect(factor.rationale).toBeDefined();
    expect(typeof factor.rationale).toBe("string");
  }

  return chain;
}

/**
 * Assert that a chain has a source link of the expected type.
 * Used for taint analysis rules (C1-C16, K6, etc.) where the source matters.
 */
export function expectSourceLink(
  chain: EvidenceChain,
  expectedType?: SourceLink["source_type"],
): SourceLink {
  const sources = chain.links.filter((l): l is SourceLink => l.type === "source");
  expect(sources.length).toBeGreaterThanOrEqual(1);

  const source = expectedType
    ? sources.find((s) => s.source_type === expectedType)
    : sources[0];

  if (!source) {
    const types = sources.map((s) => s.source_type).join(", ");
    throw new Error(
      `Expected source link of type "${expectedType}" but found: [${types}]`,
    );
  }

  // Source must have location and observed text
  expect(source.location).toBeDefined();
  // v2 locations are structured objects (or legacy strings); both render to
  // a non-empty human label via renderLocation().
  expect(renderLocation(source.location).length).toBeGreaterThan(0);
  expect(source.observed).toBeDefined();
  expect(source.observed.length).toBeGreaterThan(0);
  expect(source.rationale).toBeDefined();
  expect(source.rationale.length).toBeGreaterThan(0);

  return source;
}

/**
 * Assert that a chain has a sink link of the expected type.
 * Used for taint analysis rules where the dangerous operation matters.
 */
export function expectSinkLink(
  chain: EvidenceChain,
  expectedType?: SinkLink["sink_type"],
): SinkLink {
  const sinks = chain.links.filter((l): l is SinkLink => l.type === "sink");
  expect(sinks.length).toBeGreaterThanOrEqual(1);

  const sink = expectedType
    ? sinks.find((s) => s.sink_type === expectedType)
    : sinks[0];

  if (!sink) {
    const types = sinks.map((s) => s.sink_type).join(", ");
    throw new Error(
      `Expected sink link of type "${expectedType}" but found: [${types}]`,
    );
  }

  // Sink must have location and observed text
  expect(sink.location).toBeDefined();
  // v2 locations are structured objects (or legacy strings); both render to
  // a non-empty human label via renderLocation().
  expect(renderLocation(sink.location).length).toBeGreaterThan(0);
  expect(sink.observed).toBeDefined();
  expect(sink.observed.length).toBeGreaterThan(0);

  return sink;
}

/**
 * Assert that a chain has verification steps.
 * Used for rules that should provide actionable reviewer guidance.
 */
export function expectVerificationSteps(chain: EvidenceChain, minSteps = 1): void {
  expect(chain.verification_steps).toBeDefined();
  expect(chain.verification_steps!.length).toBeGreaterThanOrEqual(minSteps);

  for (const step of chain.verification_steps!) {
    expect(step.step_type).toBeDefined();
    expect(step.instruction).toBeDefined();
    expect(step.instruction.length).toBeGreaterThan(0);
    expect(step.target).toBeDefined();
    // v2 target is a structured Location (or legacy string); both render to
    // a non-empty human label via renderLocation().
    expect(renderLocation(step.target).length).toBeGreaterThan(0);
    expect(step.expected_observation).toBeDefined();
    expect(step.expected_observation.length).toBeGreaterThan(0);
  }
}

/**
 * Assert a chain has a threat reference (CVE, research paper, framework control).
 * Used for rules backed by specific intelligence sources.
 */
export function expectThreatReference(chain: EvidenceChain, idSubstring?: string): void {
  expect(chain.threat_reference).toBeDefined();
  expect(chain.threat_reference!.id).toBeDefined();
  expect(chain.threat_reference!.id.length).toBeGreaterThan(0);
  expect(chain.threat_reference!.title).toBeDefined();
  expect(chain.threat_reference!.relevance).toBeDefined();

  if (idSubstring) {
    expect(chain.threat_reference!.id).toContain(idSubstring);
  }
}

/**
 * Assert that a chain has an impact link with the expected type.
 */
export function expectImpactLink(
  chain: EvidenceChain,
  expectedType?: string,
): void {
  const impacts = chain.links.filter((l) => l.type === "impact");
  expect(impacts.length).toBeGreaterThanOrEqual(1);

  if (expectedType) {
    const match = impacts.find((l: any) => l.impact_type === expectedType);
    if (!match) {
      const types = impacts.map((l: any) => l.impact_type).join(", ");
      throw new Error(
        `Expected impact link of type "${expectedType}" but found: [${types}]`,
      );
    }
  }
}

/**
 * Assert that confidence is within an expected range.
 * Used for confidence calibration tests — verifying that more evidence = higher confidence.
 */
export function expectConfidenceRange(
  chain: EvidenceChain,
  min: number,
  max: number,
): void {
  expect(chain.confidence).toBeGreaterThanOrEqual(min);
  expect(chain.confidence).toBeLessThanOrEqual(max);
}

/**
 * Assert that a chain has mitigation links (present or absent).
 */
export function expectMitigationChecked(
  chain: EvidenceChain,
  mitigationType: string,
  present: boolean,
): void {
  const mitigations = chain.links.filter(
    (l) => l.type === "mitigation" && (l as any).mitigation_type === mitigationType,
  );
  expect(mitigations.length).toBeGreaterThanOrEqual(1);
  expect((mitigations[0] as any).present).toBe(present);
}

/**
 * Assert that a chain has a propagation link (data flow proof).
 * Used for taint analysis rules where the flow from source to sink matters.
 */
export function expectPropagationLink(chain: EvidenceChain): void {
  const props = chain.links.filter((l) => l.type === "propagation");
  expect(props.length).toBeGreaterThanOrEqual(1);
  expect((props[0] as any).location).toBeDefined();
  expect((props[0] as any).observed).toBeDefined();
}

/**
 * Full evidence chain validation for compliance-grade findings.
 * Combines all assertions: structure, source, sink, confidence, factors.
 * Returns the chain for further custom assertions.
 */
export function expectComplianceGradeEvidence(
  finding: TypedFinding,
  opts: {
    sourceType?: SourceLink["source_type"];
    sinkType?: SinkLink["sink_type"];
    minConfidence?: number;
    maxConfidence?: number;
    threatRefContains?: string;
    expectVerification?: boolean;
    expectImpact?: string;
  } = {},
): EvidenceChain {
  const chain = expectEvidenceChain(finding);

  if (opts.sourceType) expectSourceLink(chain, opts.sourceType);
  if (opts.sinkType) expectSinkLink(chain, opts.sinkType);
  if (opts.minConfidence !== undefined || opts.maxConfidence !== undefined) {
    expectConfidenceRange(chain, opts.minConfidence ?? 0.05, opts.maxConfidence ?? 0.99);
  }
  if (opts.threatRefContains) expectThreatReference(chain, opts.threatRefContains);
  if (opts.expectVerification) expectVerificationSteps(chain);
  if (opts.expectImpact) expectImpactLink(chain, opts.expectImpact);

  return chain;
}
