/**
 * K2 — Audit Trail Destruction, Rule Standard v2.
 *
 * REPLACES the K2 definition in
 * `packages/analyzer/src/rules/implementations/secret-exfil-detector.ts`.
 *
 * Detection is a structural AST scan (see gather.ts). Emits a v2
 * RuleResult for every destruction-sink call whose path argument
 * contains an audit-identifier token, every empty-write sink with the
 * same audit path shape, and every logger-disable primitive. Severity:
 *
 *   - critical: destruction call + NO rotation marker in enclosing scope
 *   - high:     destruction call + rotation marker in enclosing scope
 *               (still a violation — rotation without retention is not
 *                compliant — but less severe than a bare unlink)
 *   - critical: logger-disable primitive (no rotation-marker reduction)
 *
 * Zero regex literals. Zero string arrays > 5.
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
import { gatherK2, type DestructionFact, type LoggerDisableFact } from "./gather.js";
import {
  stepInspectDestructionPath,
  stepInspectDestructionSink,
  stepCheckRotationPolicy,
  stepCheckAppendOnlyStorage,
  stepInspectLoggerDisable,
} from "./verification.js";

const RULE_ID = "K2";
const RULE_NAME = "Audit Trail Destruction";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.88;

const REMEDIATION =
  "Never delete, truncate, or rename-to-/dev/null audit log files from " +
  "application code. Implement log rotation (logrotate, winston file " +
  "rotation, Python RotatingFileHandler) with an explicit retention " +
  "policy; the rotation pipeline must emit a compressed archive to an " +
  "append-only store (S3 Object Lock, Azure Immutable Blob, WORM volume) " +
  "BEFORE any deletion. Never expose logger.silent / logger.level = " +
  "\"silent\" / logging.disable toggles on a code path reachable in " +
  "production. ISO 27001 A.8.15 requires logs to be protected against " +
  "tampering AND unauthorized deletion; EU AI Act Art. 12 requires the " +
  "record to be retained for the system's full lifetime; both controls " +
  "are violated by any code path that programmatically destroys the " +
  "audit trail.";

const REF_ISO = {
  id: "ISO-27001-A.8.15",
  title: "ISO/IEC 27001:2022 Annex A Control 8.15 — Logging",
  url: "https://www.iso.org/standard/82875.html",
  relevance:
    "A.8.15 requires logs to be protected against tampering and unauthorized deletion. " +
    "Programmatic file-level destruction by application code, without an append-only " +
    "storage layer above, is the canonical failure mode this control exists to prevent.",
} as const;

function impactScenario(fact: DestructionFact): string {
  return (
    `After initial access through an MCP server compromise, the attacker invokes the ` +
    `\`${fact.sink.name}(${fact.pathExpression.slice(0, 40)})\` path to erase the ` +
    `audit record of the initial access, the lateral movement, and the data action. ` +
    `Incident response cannot reconstruct the sequence of events. Regulators ` +
    `(ISO 27001:2022 A.8.15, EU AI Act Art.12, ISO 42001 A.8.1) flag the MCP server ` +
    `as non-compliant on the record-keeping / log-protection dimensions — `+
    (fact.sink.mode === "unlink"
      ? `the audit file is removed from the filesystem.`
      : fact.sink.mode === "truncate"
        ? `the audit file is zeroed; subsequent entries do not restore the historical record.`
        : `the audit file is renamed with no archive step.`)
  );
}

function impactScenarioForDisable(fact: LoggerDisableFact): string {
  return (
    `The toggle ${fact.sink.description} disables audit emission framework-wide from ` +
    `the point of execution. All subsequent authentication failures, authorization ` +
    `rejections, tool-call errors, and deserialisation failures are silently dropped. ` +
    `An attacker who reaches this code path — or a legitimate operator who misuses the ` +
    `toggle under incident-response pressure — blinds the audit trail. ISO 27001 A.8.15 ` +
    `and EU AI Act Art.12 compliance becomes impossible on the record-keeping dimension.`
  );
}

export class AuditTrailDestructionRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK2(context);
    if (gathered.mode !== "facts") return [];

    const out: RuleResult[] = [];
    for (const fact of gathered.facts) {
      if (fact.kind === "destruction") {
        out.push(this.buildDestructionFinding(fact));
      } else {
        out.push(this.buildLoggerDisableFinding(fact));
      }
    }
    return out;
  }

  private buildDestructionFinding(fact: DestructionFact): RuleResult {
    const hasRotation = fact.rotationMarker !== null;
    const severity = hasRotation ? "high" : "critical";

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.pathLocation,
        observed: fact.pathExpression,
        rationale:
          `Audit-file path argument to the destruction call. Matched markers: ` +
          `${fact.pathMarkers.map((m) => `${m.token} (${m.kind})`).join(", ")}. ` +
          `The path resolves — statically or through a named config field — to a ` +
          `compliance-critical log / audit file whose continued existence the ` +
          `record-keeping regime depends on.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: fact.pathLocation,
        observed:
          `Path expression is passed directly as the ${fact.sink.pathArgIdx === 0 ? "first" : `#${fact.sink.pathArgIdx + 1}`} ` +
          `argument of the destruction call.`,
      })
      .sink({
        sink_type: "file-write",
        location: fact.sinkLocation,
        observed: `${fact.sink.name}: ${fact.sinkObserved.slice(0, 80)}`,
        cve_precedent: "CVE-2024-52798",
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: hasRotation,
        location: fact.rotationMarkerLocation ?? fact.sinkLocation,
        detail: hasRotation
          ? `Rotation marker \`${fact.rotationMarker?.token}\` (${fact.rotationMarker?.description}) observed in the enclosing function scope. ` +
            `The destruction MAY be a retention-bounded rotation rather than a bare deletion; severity downgraded to high. ` +
            `A reviewer must still confirm the rotation retains an immutable archive before the deletion.`
          : `No rotation / archive marker (rotate / archive / compress / gzip / S3 / putObject / logrotate) observed in the enclosing function scope. ` +
            `This is a bare deletion — the audit record is destroyed with no retention step.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: hasRotation ? "complex" : "trivial",
        scenario: impactScenario(fact),
      })
      .factor(
        "audit_path_identifier",
        fact.pathMarkers.length >= 2 ? 0.12 : 0.08,
        `Matched ${fact.pathMarkers.length} audit-identifier marker(s) in the path: ` +
          `${fact.pathMarkers.map((m) => m.token).join(", ")}. A single-marker match (e.g. ` +
          `\".log\" only) is enough to fire, but multiple markers increase confidence that ` +
          `the path truly resolves to an audit file and not a log-adjacent path.`,
      )
      .factor(
        "unmitigated_destruction_reachability",
        hasRotation ? -0.08 : 0.1,
        hasRotation
          ? `Rotation marker present in the enclosing scope — destruction MAY be bounded by a retention policy; ` +
            `confidence adjusted downward pending reviewer confirmation.`
          : `No rotation / archive step in the enclosing scope — destruction is unconditional and unretained.`,
      )
      .factor(
        "rotation_or_archive_absent",
        hasRotation ? 0 : 0.05,
        hasRotation
          ? `A rotation marker WAS found — this factor is informational.`
          : `Charter-required factor: no rotation / archive call on the destruction path. The ` +
            `ISO 27001 A.8.15 "protection" requirement is violated: destruction without retention.`,
      )
      .reference(REF_ISO)
      .verification(stepInspectDestructionPath(fact))
      .verification(stepInspectDestructionSink(fact))
      .verification(stepCheckRotationPolicy(fact))
      .verification(stepCheckAppendOnlyStorage());

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity,
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }

  private buildLoggerDisableFinding(fact: LoggerDisableFact): RuleResult {
    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: fact.sinkLocation,
        observed: fact.sinkObserved,
        rationale:
          `Logger-disable primitive — ${fact.sink.description}. The PRESENCE of this ` +
          `toggle in production code is a compliance violation under ISO 27001 A.8.15 ` +
          `independent of its runtime reachability: a toggle that blanks the audit ` +
          `stream is a pre-positioned evidence-removal primitive.`,
      })
      .propagation({
        propagation_type: "direct-pass",
        location: fact.sinkLocation,
        observed: `The toggle is the sink — no propagation hop.`,
      })
      .sink({
        sink_type: "config-modification",
        location: fact.sinkLocation,
        observed: fact.sinkObserved.slice(0, 80),
        cve_precedent: "CVE-2024-52798",
      })
      .mitigation({
        mitigation_type: "auth-check",
        present: false,
        location: fact.sinkLocation,
        detail:
          "Logger suppression is unconditional — no guard, no authorization check, no " +
          "environment gate is present between code entry and the toggle. Even when " +
          "guarded, the presence of the toggle is the compliance violation.",
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "trivial",
        scenario: impactScenarioForDisable(fact),
      })
      .factor(
        "audit_path_identifier",
        0.08,
        "Logger-disable primitive — no path is required; the toggle suppresses the entire " +
          "audit stream.",
      )
      .factor(
        "unmitigated_destruction_reachability",
        0.12,
        "No guard between entry and the toggle. The disable is fully reachable.",
      )
      .factor(
        "rotation_or_archive_absent",
        0.05,
        "Rotation is not applicable to a framework-level toggle — the toggle simply drops " +
          "subsequent events. Factor recorded for charter completeness.",
      )
      .reference(REF_ISO)
      .verification(stepInspectLoggerDisable(fact))
      .verification(stepCheckAppendOnlyStorage());

    const chain = builder.build();
    capConfidence(chain, CONFIDENCE_CAP);

    return {
      rule_id: RULE_ID,
      severity: "critical",
      owasp_category: OWASP,
      mitre_technique: MITRE,
      remediation: REMEDIATION,
      chain,
    };
  }
}

function capConfidence(chain: EvidenceChain, cap: number): void {
  if (chain.confidence <= cap) return;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K2 charter caps confidence at ${cap} — append-only storage (S3 Object Lock, ` +
      `Azure Immutable Blob, WORM) is a runtime enforcement layer not observable at ` +
      `source-file scope; a maximum-confidence claim would overstate the static evidence.`,
  });
  chain.confidence = cap;
}

registerTypedRuleV2(new AuditTrailDestructionRule());
