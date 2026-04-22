/**
 * K3 — Audit Log Tampering (Rule Standard v2).
 *
 * REPLACES the K3 class previously in
 * `packages/analyzer/src/rules/implementations/advanced-supply-chain-detector.ts`.
 */

import type { AnalysisContext } from "../../../engine.js";
import {
  type TypedRuleV2,
  type RuleResult,
  type RuleRequirements,
  type AnalysisTechnique,
  registerTypedRuleV2,
} from "../../base.js";
import {
  EvidenceChainBuilder,
  type EvidenceChain,
} from "../../../evidence.js";
import { gatherK3, type K3Fact } from "./gather.js";
import { stepsForFact } from "./verification.js";

const RULE_ID = "K3";
const RULE_NAME = "Audit Log Tampering";
const OWASP = "MCP09-logging-monitoring" as const;
const MITRE = "AML.T0054" as const;
const CONFIDENCE_CAP = 0.85;

const REMEDIATION =
  "Audit logs MUST be append-only. Remove every read → transform → write " +
  "round-trip against a persisted audit file. Open audit files with an " +
  "append-only flag (`\"a\"` / `\"a+\"` / O_APPEND) and never `\"r+\"` or " +
  "`\"w+\"`. Do NOT `sed -i` / `perl -i` an audit path from a Dockerfile or " +
  "setup script. If PII redaction is legally required (GDPR right-to-erasure), " +
  "redact at write-time before the log is persisted — never rewrite an " +
  "already-persisted record. Forward audit events to an immutable store " +
  "(WORM S3, append-only CloudWatch Logs, SIEM with WORM retention). Required " +
  "by ISO 27001:2022 A.8.15 and EU AI Act Art. 12.";

class AuditLogTamperingRule implements TypedRuleV2 {
  readonly id = RULE_ID;
  readonly name = RULE_NAME;
  readonly requires: RuleRequirements = { source_code: true };
  readonly technique: AnalysisTechnique = "structural";

  analyze(context: AnalysisContext): RuleResult[] {
    const gathered = gatherK3(context);
    if (gathered.mode !== "facts") return [];
    return gathered.facts.map((f) => this.buildFinding(f));
  }

  private buildFinding(fact: K3Fact): RuleResult {
    const readLoc = fact.readLocation ?? fact.location;
    const writeLoc = fact.writeLocation ?? fact.location;

    const builder = new EvidenceChainBuilder()
      .source({
        source_type: "file-content",
        location: readLoc,
        observed: fact.observed.slice(0, 200),
        rationale: sourceRationale(fact),
      })
      .propagation({
        propagation_type: propagationTypeFor(fact),
        location: fact.location,
        observed: propagationText(fact),
      })
      .sink({
        sink_type: "file-write",
        location: writeLoc,
        observed: sinkText(fact),
        cve_precedent: "CVE-2024-52798",
      })
      .mitigation({
        mitigation_type: "input-validation",
        present: false,
        location: fact.location,
        detail: fact.appendOnlyElsewhere
          ? `An append-only flag is visible elsewhere in ${fact.file}, but ` +
            `the flagged call at this line does not use it — policy is ` +
            `declared but locally bypassed.`
          : `No append-only enforcement observed in ${fact.file}. The ` +
            `audit file is fully mutable from within the same module.`,
      })
      .impact({
        impact_type: "config-poisoning",
        scope: "server-host",
        exploitability: "moderate",
        scenario: impactScenario(fact),
      })
      .factor(
        "audit_path_match",
        0.12,
        `Path substring "${fact.auditPath}" identifies this operation as ` +
          `targeting an audit / log / journal file.`,
      )
      .factor(
        "tampering_operation",
        0.12,
        `Tampering shape observed: ${fact.operation}.`,
      )
      .factor(
        "no_append_only_enforcement",
        fact.appendOnlyElsewhere ? 0.04 : 0.1,
        fact.appendOnlyElsewhere
          ? `Append-only token seen in the same file but not on this call.`
          : `No append-only enforcement in this module.`,
      )
      .reference({
        id: "CVE-2024-52798",
        title:
          "path-to-regexp ReDoS (exemplar CVE for log-integrity class — " +
          "log-flooding pretext + audit-destruction chain)",
        url: "https://nvd.nist.gov/vuln/detail/CVE-2024-52798",
        relevance:
          "CVE-2024-52798 is the manifest-registered exemplar for the " +
          "audit-destruction class this rule covers — a round-trip on an " +
          "audit log is the primary post-exploitation step that erases " +
          "evidence of the initial ReDoS-driven log flood.",
      });

    for (const s of stepsForFact(fact)) builder.verification(s);

    const chain = capConfidence(builder.build(), CONFIDENCE_CAP);

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

function sourceRationale(fact: K3Fact): string {
  switch (fact.kind) {
    case "read-filter-write":
      return (
        `Audit file read from "${fact.auditPath}" as the source of a ` +
        `round-trip mutation. ISO 27001 A.8.15 requires logs to be ` +
        `protected against tampering — any code path that LOADS the ` +
        `audit record in order to transform and rewrite it is, by ` +
        `construction, a tampering primitive.`
      );
    case "inplace-shell":
      return (
        `Shell in-place edit "${fact.operation}" targeting the audit ` +
        `path "${fact.auditPath}". This is a direct audit-integrity ` +
        `violation — the command writes to a persisted forensic record ` +
        `without going through append-only logging infrastructure.`
      );
    case "rw-mode-open":
      return (
        `File opened with in-place mutation flag ${fact.operation} on ` +
        `audit path "${fact.auditPath}". Any non-append flag on an audit ` +
        `file permits seek + overwrite of existing records.`
      );
    case "timestamp-forgery":
      return (
        `Timestamp modification (${fact.operation}) on audit file ` +
        `"${fact.auditPath}". Backdating a log file defeats correlation ` +
        `with external time-series evidence without altering any line.`
      );
  }
}

function propagationTypeFor(fact: K3Fact): "variable-assignment" | "direct-pass" {
  return fact.kind === "read-filter-write" ? "variable-assignment" : "direct-pass";
}

function propagationText(fact: K3Fact): string {
  switch (fact.kind) {
    case "read-filter-write":
      return `Read → transform → write round-trip; transform removes / replaces rows in memory before write-back.`;
    case "inplace-shell":
      return `Shell pipe: ${fact.operation} rewrites the file in place.`;
    case "rw-mode-open":
      return `File descriptor held open for in-place mutation (${fact.operation}).`;
    case "timestamp-forgery":
      return `Metadata-only mutation — file contents untouched, mtime/atime rewritten.`;
  }
}

function sinkText(fact: K3Fact): string {
  switch (fact.kind) {
    case "read-filter-write":
      return `writeFile* on "${fact.auditPath}" — mutated audit content persisted.`;
    case "inplace-shell":
      return `${fact.operation} persisted overwrite of "${fact.auditPath}".`;
    case "rw-mode-open":
      return `Descriptor on "${fact.auditPath}" held with flag ${fact.operation} — seek+write permitted.`;
    case "timestamp-forgery":
      return `Forged timestamps persisted on "${fact.auditPath}".`;
  }
}

function impactScenario(fact: K3Fact): string {
  const base =
    `The audit trail for this server is no longer a faithful record of ` +
    `events. Incident response cannot attribute authentication failures, ` +
    `tool-call outcomes, or authorisation decisions; ISO 27001 A.8.15 and ` +
    `EU AI Act Art. 12 treat this as strictly worse than log deletion ` +
    `because it creates a false record of what the AI agent did.`;
  if (fact.kind === "timestamp-forgery") {
    return (
      base +
      ` Time-based forensics are defeated: the file looks pristine to a ` +
      `SIEM checking for last-modified consistency.`
    );
  }
  return base;
}

function capConfidence(chain: EvidenceChain, cap: number): EvidenceChain {
  if (chain.confidence <= cap) return chain;
  chain.confidence_factors.push({
    factor: "charter_confidence_cap",
    adjustment: cap - chain.confidence,
    rationale:
      `K3 charter caps confidence at ${cap} — legitimate PII redaction ` +
      `pipelines perform a read-transform-write round-trip that a static ` +
      `rule cannot always distinguish from malicious tampering without a ` +
      `runtime policy assertion.`,
  });
  chain.confidence = cap;
  return chain;
}

registerTypedRuleV2(new AuditLogTamperingRule());

export { AuditLogTamperingRule };
