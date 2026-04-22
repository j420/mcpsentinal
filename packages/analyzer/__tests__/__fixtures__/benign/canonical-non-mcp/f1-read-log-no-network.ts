/**
 * F1 negative — a server with read + log tools but NO external
 * network egress. The lethal trifecta requires all three legs.
 */
import type { BenignFixture } from "../types.js";
import { makeCanonicalFixture } from "./_helpers.js";

export const f1ReadLogFixture: BenignFixture = makeCanonicalFixture({
  id: "canonical-non-mcp/f1-read-plus-log-no-egress",
  name: "local-diagnostic",
  why:
    "A server that reads a local audit trail and writes a local " +
    "diagnostic log — no external-egress tool present. Stresses F1 " +
    "lethal-trifecta negative.",
  description:
    "Local-only diagnostic helper. Reads a local audit trail and " +
    "writes a summary to the same machine's log file.",
  tools: [
    {
      name: "read_audit_entry",
      description:
        "Return a single audit entry by id from the local audit store.",
      input_schema: {
        type: "object",
        properties: {
          entry_id: { type: "string", pattern: "^AE-[0-9]{6}$" },
        },
        required: ["entry_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "append_diagnostic_line",
      description:
        "Append a one-line diagnostic entry to the local diagnostic log.",
      input_schema: {
        type: "object",
        properties: {
          line: { type: "string", maxLength: 512 },
        },
        required: ["line"],
        additionalProperties: false,
      },
    },
  ],
  source_code: `
    import { readFile, appendFile } from "node:fs/promises";

    export async function readAuditEntry(entryId) {
      const raw = await readFile("/var/lib/app/audit.jsonl", "utf8");
      for (const line of raw.split("\\n")) {
        if (line.includes(entryId)) return JSON.parse(line);
      }
      return null;
    }

    export async function appendDiagnosticLine(line) {
      await appendFile("/var/log/app/diag.log", line + "\\n", "utf8");
      return { ok: true };
    }
  `,
});
