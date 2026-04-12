/**
 * Rule: eu-ai-act-art12-record-keeping
 * Author personas: Senior MCP Threat Researcher (CHARTER.md) +
 *                  Senior MCP Security Engineer (this file).
 *
 * Detection strategy:
 *   1. Inspect source files map for structured-logging library bindings.
 *   2. Check `initialize_metadata.server_version` for a stable version
 *      pin (Art.12 requires lifetime traceability — replay needs this).
 *   3. Check `connection_metadata` heuristics (transport type) and the
 *      declared logging capability for a durable sink.
 *   4. Bundle the Article 12 failures.
 */

import type { AnalysisContext } from "@mcp-sentinel/analyzer";
import { createHash } from "node:crypto";

import {
  ComplianceRule,
  makeBundleId,
  type ComplianceRuleMetadata,
} from "../../base-rule.js";
import type {
  EvidenceBundle,
  EvidencePointer,
  JudgedTestResult,
  RawTestResult,
} from "../../../types.js";

interface Art12Failure {
  id:
    | "no-structured-logger"
    | "no-server-version-pin"
    | "no-declared-logging-capability"
    | "no-source-files";
  description: string;
}

interface Art12Facts {
  art12_failures: Art12Failure[];
  has_structured_logger: boolean;
  has_server_version_pin: boolean;
  declared_logging_capability: boolean;
}

const STRUCTURED_LOGGER_NAMES: readonly string[] = [
  "pino",
  "winston",
  "bunyan",
  "structlog",
];

const METADATA: ComplianceRuleMetadata = {
  id: "eu-ai-act-art12-record-keeping",
  name: "EU AI Act Article 12 — Lifetime Record-Keeping",
  severity: "high",
  intent:
    "An MCP server in a high-risk EU AI Act pipeline MUST emit lifetime-replayable structured records on every tool invocation.",
  applies_to: [
    {
      framework: "eu_ai_act",
      category: "Article 12 — Record Keeping",
      control: "Art.12",
      sub_control: "Art.12(1-3)",
    },
  ],
  threat_refs: [
    {
      id: "EU-AI-ACT-ART12-1",
      title: "EU AI Act Art.12(1) — automatic recording mandate",
      url: "https://artificialintelligenceact.eu/article/12/",
      year: 2024,
      relevance: "Direct legal basis for the rule.",
    },
    {
      id: "EU-AI-ACT-ART12-2",
      title: "EU AI Act Art.12(2) — lifetime traceability",
      year: 2024,
      relevance: "Defines the replay-ability requirement that this rule structurally checks.",
    },
  ],
  strategies: ["audit-erasure", "shadow-state", "boundary-leak"],
  remediation:
    "Adopt a structured logger (pino/winston/bunyan/structlog), persist to durable storage with monotonic UTC timestamps, include the parameter hash and pinned server version on every record, and emit a daily integrity hash over the log batch.",
};

class EUAIActArt12RecordKeepingRule extends ComplianceRule {
  readonly metadata = METADATA;

  gatherEvidence(context: AnalysisContext): EvidenceBundle {
    const failures: Art12Failure[] = [];
    const pointers: EvidencePointer[] = [];

    const hasStructuredLogger = inspectSourceForLoggers(context);
    if (!hasStructuredLogger) {
      failures.push({
        id: "no-structured-logger",
        description:
          "No binding to a recognized structured logging library found in source files.",
      });
      pointers.push({
        kind: "source-file",
        label: "no structured logger binding",
        location: "source_files",
      });
    }

    const versionPin = context.initialize_metadata?.server_version ?? null;
    const hasVersionPin = typeof versionPin === "string" && versionPin.length > 0;
    if (!hasVersionPin) {
      failures.push({
        id: "no-server-version-pin",
        description:
          "initialize_metadata.server_version is missing or empty — replay across time is impossible without a stable version pin.",
      });
      pointers.push({
        kind: "initialize-field",
        label: "missing server_version",
        location: "initialize_metadata.server_version",
      });
    }

    const declaredLogging = context.declared_capabilities?.logging === true;
    if (!declaredLogging) {
      failures.push({
        id: "no-declared-logging-capability",
        description: "Server does not declare a `logging` capability in its initialize response.",
      });
      pointers.push({
        kind: "capability",
        label: "logging capability not declared",
        location: "capabilities.logging",
      });
    }

    if (!context.source_files && !context.source_code) {
      failures.push({
        id: "no-source-files",
        description: "No source available — Article 12 compliance cannot be structurally proven.",
      });
    }

    const facts: Art12Facts = {
      art12_failures: failures,
      has_structured_logger: hasStructuredLogger,
      has_server_version_pin: hasVersionPin,
      declared_logging_capability: declaredLogging,
    };

    const summary =
      failures.length > 0
        ? `${failures.length} EU AI Act Art.12 record-keeping failure(s) detected`
        : `EU AI Act Art.12 record-keeping signals all present`;

    const factsJson = JSON.stringify(facts);
    const contentHash = createHash("sha256")
      .update(`${context.server.id}::${factsJson}`)
      .digest("hex")
      .slice(0, 16);

    return {
      bundle_id: makeBundleId(this.metadata.id, context.server.id, contentHash),
      rule_id: this.metadata.id,
      server_id: context.server.id,
      content_hash: contentHash,
      summary,
      facts: facts as unknown as Record<string, unknown>,
      pointers,
      deterministic_violation: failures.length > 0,
    };
  }

  judge(bundle: EvidenceBundle, raw: RawTestResult): JudgedTestResult {
    const facts = bundle.facts as unknown as Art12Facts;
    const failures = facts.art12_failures ?? [];

    if (raw.verdict !== "fail") {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects non-fail verdict (${raw.verdict}).`,
      };
    }
    if (failures.length === 0) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: "Judge rejects: no Art.12 failures in deterministic gather.",
      };
    }
    const ref = failures.find((f) => raw.evidence_path_used.includes(f.id));
    if (!ref) {
      return {
        ...raw,
        judge_confirmed: false,
        judge_rationale: `Judge rejects: evidence_path_used (${raw.evidence_path_used}) does not reference any Art.12 failure id (${failures.map((f) => f.id).join(", ")}).`,
      };
    }
    return {
      ...raw,
      judge_confirmed: true,
      judge_rationale: `Judge confirms: Art.12 failure '${ref.id}' — ${ref.description}`,
    };
  }
}

function inspectSourceForLoggers(context: AnalysisContext): boolean {
  const files = context.source_files;
  if (files && files.size > 0) {
    for (const content of files.values()) {
      if (STRUCTURED_LOGGER_NAMES.some((name) => content.includes(name))) {
        return true;
      }
    }
    return false;
  }
  const src = context.source_code ?? "";
  if (!src) return false;
  return STRUCTURED_LOGGER_NAMES.some((name) => src.includes(name));
}

export const euAIActArt12RecordKeepingRule = new EUAIActArt12RecordKeepingRule();
