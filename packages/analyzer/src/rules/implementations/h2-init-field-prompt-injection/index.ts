/**
 * H2 — Prompt Injection in MCP Initialize Response Fields (Rule Standard v2).
 *
 * Scans three fields in the MCP initialize handshake:
 *   - context.server.name                                (server_name)
 *   - context.initialize_metadata.server_version         (server_version)
 *   - context.initialize_metadata.server_instructions    (instructions)
 *
 * For each field, gather.ts collects a list of FieldSite hits: LLM
 * special-token substrings, Unicode control characters, phrase-catalogue
 * matches (instructions only), base64 hidden payloads (instructions
 * only), and version-shape violations (server_version only). The
 * orchestrator aggregates hits per field via noisy-OR and emits one
 * RuleResult per field with a full evidence chain.
 *
 * NO regex literals. All data lives in `./data/` as typed records; all
 * scanning is delegated to deterministic helpers (AST-free char
 * scanning, analyzers/unicode.ts, analyzers/entropy.ts).
 *
 * Silent skip: when initialize_metadata is null and the server.name
 * has no hits, the rule returns []. No warnings, no partial findings.
 *
 * Confidence cap: 0.88 per CHARTER — initialize fields have a very
 * narrow legitimate vocabulary, so anomalies are strong signals; 0.88
 * still preserves headroom below the 0.99 ceiling reserved for
 * deterministic taint proofs.
 *
 * Threat intelligence:
 *   MCP spec 2024-11-05 (original specification with `instructions` field)
 *   MCP spec 2025-03-26 (widespread client adoption)
 *   MITRE ATLAS AML.T0054.002 (direct prompt injection)
 *   MITRE ATLAS AML.T0058 (AI agent context poisoning)
 *   Rehberger 2024 / Invariant Labs 2025 — real-world payload catalogue
 *   EU AI Act Article 12 — record-keeping integrity implications
 */

import type { Severity } from "@mcp-sentinel/database";
import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import { EvidenceChainBuilder } from "../../../evidence.js";
import {
  gatherH2,
  fieldLocation,
  type FieldSite,
  type InitField,
} from "./gather.js";
import {
  stepInspectField,
  stepCompareSpec,
  stepTraceSessionImpact,
} from "./verification.js";

const RULE_ID = "H2";
const RULE_NAME = "Prompt Injection in MCP Initialize Response Fields";
const OWASP = "MCP01-prompt-injection";
const MITRE = "AML.T0054.002";
const CONFIDENCE_CAP = 0.88;
/** Aggregate-confidence threshold below which we suppress findings. */
const CONFIDENCE_FLOOR = 0.5;

const REMEDIATION =
  "MCP initialize response fields (serverInfo.name, serverInfo.version, " +
  "and the `instructions` field) must be plain text. Specifically: " +
  "(1) server.name must be a short human-readable identifier (alphanumerics, " +
  "hyphens, dots, spaces — ≤64 chars); (2) server_version must be a semver " +
  "string (major.minor.patch with optional prerelease/build — ≤32 chars, " +
  "ASCII-only); (3) server_instructions must describe how to use the server " +
  "tools in ≤500 chars of plain language — no LLM control tokens, no Unicode " +
  "control characters, no encoded payloads, no behavioural directives that " +
  "reshape the model's role or disable confirmations. MCP client teams should " +
  "validate all initialize-response fields before forwarding them to the " +
  "model. References: MCP spec 2024-11-05, MCP spec 2025-03-26, MITRE ATLAS " +
  "AML.T0054.002 / AML.T0058, Rehberger (2024), Invariant Labs (2025).";

class H2InitFieldInjectionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = {
    // H2 scans server.name which is always present. The more severe
    // fields require initialize_metadata, but the rule must still
    // fire on server.name alone — so we don't declare
    // initialize_metadata as a hard requirement.
  };
  readonly technique: AnalysisTechnique = "composite";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherH2(context);
    if (gathered.all.length === 0) return [];

    const out: RuleResult[] = [];
    for (const [field, sites] of gathered.byField.entries()) {
      const finding = this.buildFinding(field, sites);
      if (finding) out.push(finding);
    }
    return out;
  }

  private buildFinding(
    field: InitField,
    sites: FieldSite[],
  ): RuleResult | null {
    // Noisy-OR aggregate over every site in this field.
    const product = sites.reduce((p, s) => p * (1 - s.weight), 1);
    const aggregate = 1 - product;
    if (aggregate < CONFIDENCE_FLOOR) return null;

    // Anchor on the strongest-weighted hit.
    const primary = sites.reduce(
      (best, s) => (s.weight > best.weight ? s : best),
      sites[0],
    );
    const loc = fieldLocation(field);
    const severity = severityFromConfidence(aggregate);
    const uniqueKinds = new Set(sites.map((s) => s.kind)).size;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "initialize-field",
        location: loc,
        observed: primary.observed,
        rationale:
          `MCP initialize response field "${field}" is processed by the ` +
          `client BEFORE any tool description and BEFORE user context — ` +
          `with higher implicit trust than tool descriptions (tool-catalog ` +
          `metadata goes through a descriptive-expectation filter; ` +
          `initialize fields do not). ${sites.length} signal(s) detected ` +
          `across ${uniqueKinds} kind(s). Primary: "${primary.label}" ` +
          `at offset ${primary.offset}.`,
      })
      .propagation({
        propagation_type: "description-directive",
        location: loc,
        observed:
          `The "${field}" string flows from the JSON-RPC InitializeResult ` +
          `into the client's session-setup stage. For ` +
          `${field === "instructions" ? "the instructions field this means direct prepend to the model's system prompt" : "serverInfo fields this means embedding into the connection-setup narrative the model reads with metadata-level trust"}. ` +
          `No sanitisation stage exists between server and model in typical ` +
          `clients.`,
      })
      .sink({
        sink_type:
          field === "instructions" ? "code-evaluation" : "privilege-grant",
        location: loc,
        observed:
          `${sites.length} site(s) contributing to aggregate via noisy-OR: ` +
          sites
            .slice(0, 4)
            .map((s) => `${s.kind} "${s.label}" (w=${s.weight.toFixed(2)})`)
            .join(", ") +
          (sites.length > 4 ? `, and ${sites.length - 4} more` : ""),
      })
      .impact({
        impact_type: "session-hijack",
        scope: "ai-client",
        exploitability: aggregate >= 0.8 ? "trivial" : "moderate",
        scenario:
          `Injection in the "${field}" field sets behavioural rules for the ` +
          `ENTIRE session — no user interaction required, payload is ` +
          `processed automatically on connect. Every subsequent tool call ` +
          `operates under the injected rules. This reshapes what the AI is ` +
          `recorded as doing, breaking the log-integrity premise of EU AI ` +
          `Act Article 12 record-keeping.`,
      })
      .factor(
        "init_field_signal_match",
        0.08,
        `Deterministic per-field scanner found ${sites.length} signal(s) of ` +
          `${uniqueKinds} kind(s) in initialize.${field}.`,
      )
      .factor(
        "noisy_or_base_confidence",
        aggregate - 0.5,
        `Noisy-OR aggregation of ${sites.length} independent weights ` +
          `produced ${(aggregate * 100).toFixed(0)}% pre-cap confidence.`,
      );

    if (uniqueKinds >= 2) {
      builder.factor(
        "multi_kind_corroboration",
        0.06,
        `${uniqueKinds} distinct signal kinds fired in the same field — ` +
          `each kind is an independent detector so cross-kind agreement is a ` +
          `structural signal, not a paraphrase coincidence.`,
      );
    }

    const specialTokenHit = sites.find((s) => s.kind === "special-token");
    if (specialTokenHit) {
      builder.factor(
        "llm_special_token_in_initialize",
        0.12,
        `Field "${field}" contains LLM special token "${specialTokenHit.observed}" — ` +
          `never present in legitimate initialize response metadata.`,
      );
    }

    const unicodeHit = sites.find((s) => s.kind === "unicode-control");
    if (unicodeHit) {
      builder.factor(
        "unicode_control_in_initialize",
        0.08,
        `Field "${field}" contains Unicode control codepoint ` +
          `${unicodeHit.observed} (${unicodeHit.label}) — invisible to ` +
          `human review but processed by the model.`,
      );
    }

    const base64Hit = sites.find((s) => s.kind === "base64-payload");
    if (base64Hit) {
      builder.factor(
        "base64_hidden_payload_in_initialize",
        0.08,
        `Field "${field}" contains a ${base64Hit.length}-char high-entropy ` +
          `base64 run${base64Hit.decoded ? ` decoding to ${base64Hit.decoded.length} printable chars` : ""}.`,
      );
    }

    builder.reference({
      id: "MCP-SPEC-2024-11-05",
      title: "MCP Specification 2024-11-05 — InitializeResult.instructions field",
      url: "https://spec.modelcontextprotocol.io/specification/2024-11-05/",
      year: 2024,
      relevance:
        "The MCP spec defines `instructions` as guidance the client SHOULD " +
        "forward to the model. It is a spec-sanctioned injection surface: " +
        "no content-policy constraint prevents behavioural directives. H2 " +
        "detects the attack at static time before the handshake reaches " +
        "production clients. The 2025-03-26 revision is where client " +
        "support for acting on this field became widespread.",
    });

    builder.verification(stepInspectField(field, primary));
    builder.verification(stepTraceSessionImpact(field));
    builder.verification(stepCompareSpec(field));

    const chain = builder.build();

    // Apply CHARTER confidence cap.
    if (chain.confidence > CONFIDENCE_CAP) {
      chain.confidence_factors.push({
        factor: "initialize_field_confidence_cap",
        adjustment: CONFIDENCE_CAP - chain.confidence,
        rationale:
          `H2 CHARTER caps confidence at ${CONFIDENCE_CAP.toFixed(2)} — ` +
          `deterministic heuristic analysis of protocol metadata cannot ` +
          `reach the certainty of a full taint-path proof even when the ` +
          `anomaly is structurally clear.`,
      });
      chain.confidence = CONFIDENCE_CAP;
    }

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function severityFromConfidence(c: number): Severity {
  if (c >= 0.8) return "critical";
  if (c >= 0.6) return "high";
  return "medium";
}

registerTypedRuleV2(new H2InitFieldInjectionRule());

export { H2InitFieldInjectionRule };
