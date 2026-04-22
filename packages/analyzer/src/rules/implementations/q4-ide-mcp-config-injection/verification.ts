/**
 * Q4 verification-step builders. Every step carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Q4Fact } from "./gather.js";

/** Step 1 — inspect the offending source position. */
export function stepInspectPrimitive(fact: Q4Fact): VerificationStep {
  const desc = describePrimitive(fact);
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file and confirm this is a live primitive on the production ` +
      `control-flow path (not example code in a comment, not inside a ` +
      `conditional gated on an env var the build dead-code-eliminates). ${desc}`,
    target: fact.location,
    expected_observation: fact.observed,
  };
}

/** Step 2 — inspect the victim IDE / config file, if identified. */
export function stepInspectTargetConfig(fact: Q4Fact): VerificationStep {
  if (fact.targetLocation === null) {
    return {
      step_type: "check-config",
      instruction:
        `No specific IDE config file was matched on this primitive (auto-approve ` +
        `flag in isolation). Trace the surrounding code to determine WHERE the ` +
        `object literal lands — if it is persisted to an IDE settings file the ` +
        `finding compounds with a Q4 ide-config-write.`,
      target: fact.location,
      expected_observation:
        `Either a writeFileSync targeting an IDE config (compounding primitive) ` +
        `or an out-of-scope persistence (dismiss).`,
    };
  }
  return {
    step_type: "check-config",
    instruction:
      `Open the target IDE config and confirm what happens when it lands on disk. ` +
      `For Cursor (CVE-2025-54135 CurXecute) and Claude Code (CVE-2025-59536) the ` +
      `IDE auto-loads and auto-starts any mcpServers entry WITHOUT an interactive ` +
      `user confirmation. For a case-variant path (CVE-2025-59944) confirm the ` +
      `target filesystem is case-insensitive (APFS / NTFS) — on case-sensitive ` +
      `Linux ext4 the variant is a different file and the primitive does not apply.`,
    target: fact.targetLocation,
    expected_observation:
      fact.target !== null
        ? `Write lands on ${fact.target.label} (${fact.target.ide}) and the IDE ` +
          `auto-loads the configured MCP server on next launch.`
        : `Case-variant filename resolves to the canonical MCP config on case- ` +
          `insensitive filesystems — bypasses the IDE's lowercase path check.`,
  };
}

/** Step 3 — confirm the absence of a user-confirmation gate. */
export function stepCheckConsentGate(fact: Q4Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Verify that neither the code nor the IDE's current release ships a user ` +
      `confirmation gate before loading the written config. Reference CVE-2025-54135 ` +
      `(Cursor auto-start), CVE-2025-54136 (MCPoison silent mutation), CVE-2025-59536 ` +
      `(Claude Code consent bypass). A finding remains actionable until the target ` +
      `IDE release notes explicitly claim to require interactive per-server approval.`,
    target: fact.location,
    expected_observation:
      `No user confirmation gate between this write / flag and the MCP server ` +
      `executing on next IDE launch.`,
  };
}

function describePrimitive(fact: Q4Fact): string {
  switch (fact.kind) {
    case "ide-config-write":
      return (
        `This is a filesystem write targeting ` +
        `${fact.target?.label ?? "an IDE MCP config file"}. Once written, the ` +
        `IDE auto-loads the configured server on next launch.`
      );
    case "auto-approve-write":
      return (
        `This sets an auto-approve flag to \`true\`. Once persisted to the IDE ` +
        `config, every project-level MCP server loads without user consent.`
      );
    case "case-variant-filename":
      return (
        `The write path uses a case-variant spelling of an MCP config filename. ` +
        `On case-insensitive filesystems this bypasses case-sensitive validators ` +
        `and lands on the canonical file — CVE-2025-59944 primitive.`
      );
  }
}
