/**
 * K3 verification steps — every target a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { K3Fact } from "./gather.js";

export function stepsForFact(fact: K3Fact): VerificationStep[] {
  switch (fact.kind) {
    case "read-filter-write":
      return stepsForRoundTrip(fact);
    case "inplace-shell":
      return stepsForShell(fact);
    case "rw-mode-open":
      return stepsForRwMode(fact);
    case "timestamp-forgery":
      return stepsForTimestamp(fact);
  }
}

function stepsForRoundTrip(fact: K3Fact): VerificationStep[] {
  const readLoc = fact.readLocation ?? fact.location;
  const writeLoc = fact.writeLocation ?? fact.location;
  return [
    {
      step_type: "inspect-source",
      instruction:
        `Open the file at the read site. Confirm that the call reads ` +
        `"${fact.auditPath}"-family audit file — not a derived / staging ` +
        `file. An ISO 27001 A.8.15 auditor needs the read to be against ` +
        `the persisted audit record, not a pre-write buffer.`,
      target: readLoc,
      expected_observation:
        `A readFile* / createReadStream call whose first argument text ` +
        `contains "${fact.auditPath}".`,
    },
    {
      step_type: "inspect-source",
      instruction:
        `Open the file at the write site. Confirm the write targets the ` +
        `SAME audit path as the read — this is the round-trip that makes ` +
        `the log no longer a faithful record.`,
      target: writeLoc,
      expected_observation:
        `A writeFile* / createWriteStream / appendFile* call whose path ` +
        `text contains "${fact.auditPath}".`,
    },
    {
      step_type: "trace-flow",
      instruction:
        `Follow the value returned by the read call through the file. ` +
        `Between the read and the write there must be a transform (filter ` +
        `/ replace / slice / splice / map / reduce). If the transform is ` +
        `legitimate redaction (PII, GDPR, anonymisation) the rule would ` +
        `have excluded this line — therefore any surviving finding means ` +
        `the transform is NOT a documented redaction.`,
      target: fact.location,
      expected_observation:
        `A chain of calls applying a transform between the read and the ` +
        `write. The transform is what rewrites the log content.`,
    },
    {
      step_type: "check-config",
      instruction:
        `Open package.json / mcp.json and confirm whether an append-only ` +
        `audit policy is declared. An append-only WAL configured via ` +
        `server manifest reduces residual risk (but does not fully ` +
        `mitigate this finding — the round-trip is still a policy ` +
        `violation).`,
      target: {
        kind: "config",
        file: "package.json",
        json_pointer: "/mcp/audit/append_only",
      },
      expected_observation:
        fact.appendOnlyElsewhere
          ? `An append-only flag ("a" / "a+" / O_APPEND) is visible ` +
            `elsewhere in the file, but not on this call.`
          : `No append-only flag observed anywhere in this module — the ` +
            `entire audit path is mutable.`,
    },
  ];
}

function stepsForShell(fact: K3Fact): VerificationStep[] {
  return [
    {
      step_type: "inspect-source",
      instruction:
        `Open this line and confirm the shell command is an in-place ` +
        `rewrite ("${fact.operation}") targeting an audit file matching ` +
        `"${fact.auditPath}". In-place shell edits on persisted audit ` +
        `records are a direct violation of ISO 27001 A.8.15.`,
      target: fact.location,
      expected_observation:
        `A string literal or command invocation whose text includes ` +
        `"${fact.operation}" and a file path containing "${fact.auditPath}".`,
    },
    {
      step_type: "trace-flow",
      instruction:
        `Check how this command is reached at runtime — a Dockerfile RUN ` +
        `line, a post-install hook, a tool-handler exec. Any of these ` +
        `indicates the mutation is deployable; a dead-code location still ` +
        `violates audit integrity on inspection.`,
      target: fact.location,
      expected_observation: `The invocation is on the normal control-flow path.`,
    },
    appendOnlyConfigStep(fact),
  ];
}

function stepsForRwMode(fact: K3Fact): VerificationStep[] {
  return [
    {
      step_type: "inspect-source",
      instruction:
        `Open this call and confirm the file is opened with ${fact.operation} ` +
        `on an audit path ("${fact.auditPath}"). Any non-append mode on an ` +
        `audit file permits in-place mutation of existing records.`,
      target: fact.location,
      expected_observation:
        `An open / openSync call whose flag argument is one of r+ / w+ / a+.`,
    },
    {
      step_type: "trace-flow",
      instruction:
        `Trace the file descriptor. Confirm whether a seek + write is ` +
        `performed on the descriptor — that seek+write pair is the actual ` +
        `tampering.`,
      target: fact.location,
      expected_observation:
        `A subsequent write / writeSync / write stream call on the ` +
        `descriptor returned by this open.`,
    },
    appendOnlyConfigStep(fact),
  ];
}

function stepsForTimestamp(fact: K3Fact): VerificationStep[] {
  return [
    {
      step_type: "inspect-source",
      instruction:
        `Open this call and confirm ${fact.operation}(...) is applied to ` +
        `an audit file ("${fact.auditPath}"). Forging mtime / atime ` +
        `defeats time-based forensics without altering any log line.`,
      target: fact.location,
      expected_observation:
        `A utimes-family call whose first argument includes "${fact.auditPath}".`,
    },
    appendOnlyConfigStep(fact),
  ];
}

function appendOnlyConfigStep(fact: K3Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open the project's audit configuration (package.json / mcp.json / ` +
      `systemd unit). Confirm whether an append-only policy is in force. ` +
      `Absence is the finding — ${fact.file} has full write access to ` +
      `"${fact.auditPath}".`,
    target: {
      kind: "config",
      file: "package.json",
      json_pointer: "/mcp/audit/append_only",
    },
    expected_observation: fact.appendOnlyElsewhere
      ? `An append-only token is present in this module's file-open ` +
        `flags, but the flagged call circumvents it.`
      : `No append-only audit policy declared.`,
  };
}
