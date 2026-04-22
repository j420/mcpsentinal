/**
 * K2 verification-step builders. Each step carries a structured
 * `target: Location` (v2 standard §4).
 *
 * Zero regex, zero long string arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { DestructionFact, LoggerDisableFact } from "./gather.js";

export function stepInspectDestructionPath(fact: DestructionFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the destruction-call path argument ` +
      `\`${fact.pathExpression.slice(0, 120)}\` really does resolve — statically or via ` +
      `configuration — to a compliance-critical audit file. Matched audit markers: ` +
      `${fact.pathMarkers.map((m) => m.token).join(", ")}. If the path is a config field ` +
      `(e.g. \`config.auditPath\`), cross-reference with the server's default config ` +
      `JSON to confirm the default target is an audit file.`,
    target: fact.pathLocation,
    expected_observation:
      `Path expression that resolves to an audit / log / journal file, matched by at ` +
      `least one of ${fact.pathMarkers.length} marker(s).`,
  };
}

export function stepInspectDestructionSink(fact: DestructionFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call is \`${fact.sink.name}\` ` +
      `(${fact.sink.description}). The destruction mode is \`${fact.sink.mode}\`: ` +
      (fact.sink.mode === "unlink"
        ? `file is removed from the filesystem — historical audit record is permanently lost.`
        : fact.sink.mode === "truncate"
          ? `file is emptied while keeping the path — historical records are destroyed but the ` +
            `writer can continue to emit records after the call.`
          : `file is renamed — if no archival step follows, the rename is effectively a delete.`),
    target: fact.sinkLocation,
    expected_observation:
      `A \`${fact.sink.name}(...)\` call whose path argument was the expression verified in ` +
      `the previous step.`,
  };
}

export function stepCheckRotationPolicy(fact: DestructionFact): VerificationStep {
  if (fact.rotationMarker && fact.rotationMarkerLocation) {
    return {
      step_type: "inspect-source",
      instruction:
        `A rotation / archive marker \`${fact.rotationMarker.token}\` was observed in the ` +
        `enclosing function scope. Confirm whether this is a real retention mechanism ` +
        `(archive compressed, uploaded to immutable storage, retention-policy-driven) or ` +
        `merely a comment / placeholder. A rotation call that deletes WITHOUT retaining a ` +
        `copy is still a compliance violation under ISO 27001 A.8.15.`,
      target: fact.rotationMarkerLocation,
      expected_observation:
        `A rotation / archival step whose output SURVIVES the deletion call at the sink. ` +
        `If no such retention exists, severity stays critical.`,
    };
  }
  return {
    step_type: "inspect-source",
    instruction:
      `No rotation / archive marker (rotate / archive / compress / gzip / S3 / putObject / ` +
      `logrotate) was observed in the enclosing function scope. Confirm by scanning the ` +
      `surrounding ~40 lines of the same function. If a legitimate rotation IS present but ` +
      `the tokens differ, the marker list in data/config.ts should be extended.`,
    target: fact.sinkLocation,
    expected_observation:
      `No rotation step above or below the destruction call — this is a bare deletion.`,
  };
}

export function stepCheckAppendOnlyStorage(): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      "Verify whether the audit logs are stored on append-only / immutable storage that " +
      "prevents programmatic deletion regardless of application code: AWS S3 Object Lock " +
      "with retention, Azure Immutable Blob Storage, GCS retention policies, or a WORM " +
      "volume. If immutable storage is enforced, the runtime impact of this finding is " +
      "constrained to the in-process buffer; the finding remains because the source-code " +
      "pattern is still a compliance violation under ISO 27001 A.8.15.",
    target: {
      kind: "config",
      file: "deployment/terraform-or-cloudformation",
      json_pointer: "/audit-storage",
    },
    expected_observation:
      "Confirmation whether audit storage is immutable. If not, the destruction call is " +
      "directly exploitable.",
  };
}

export function stepInspectLoggerDisable(fact: LoggerDisableFact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the toggle is reachable on the ` +
      `normal control-flow path — not guarded by a test-only flag, not inside a ` +
      `conditional the production build dead-code-eliminates. The toggle (` +
      `${fact.sink.description}) disables logging for the entire logger instance / ` +
      `framework; any subsequent audit emission is silently dropped.`,
    target: fact.sinkLocation,
    expected_observation:
      `An unconditional ${fact.sink.name === "logger.silent"
        ? "logger.silent = true"
        : fact.sink.name === "logger.level"
          ? "logger.level = \"silent\""
          : `${fact.sink.name}(...)`} on the startup path.`,
  };
}
