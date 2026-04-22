/**
 * Stresses K2 Audit Trail Destruction. The code appears to call
 * console.warn for audit events, but an intentional runtime
 * replacement routes the calls to a durable append-only audit sink.
 * The `console.warn` call itself is the DEV fallback, not a trail
 * destroyer. K2 fires on pattern-match of console writes on audit
 * paths; here the data does not go to /dev/null.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import { appendFileSync } from "node:fs";

const AUDIT_LOG_PATH = "/var/log/audit/app-audit.jsonl";

/** Durable append-only audit sink. */
function writeAudit(event: Record<string, unknown>): void {
  appendFileSync(AUDIT_LOG_PATH, JSON.stringify(event) + "\\n", { flag: "a" });
}

// Route console.warn into the audit sink at startup. This is the
// compatibility shim — the real sink is appendFileSync above.
const originalWarn = console.warn.bind(console);
console.warn = (msg: unknown, ...rest: unknown[]) => {
  writeAudit({ kind: "warn", msg: String(msg), rest });
  originalWarn(msg, ...rest);
};

export function recordAuditEvent(kind: string, detail: Record<string, unknown>) {
  writeAudit({ kind, ...detail, at: new Date().toISOString() });
}
`;

export const k2AuditLoggerFallbackFixture: BenignFixture = {
  id: "edge-of-spec/k2-audit-logger-fallback",
  bucket: "edge-of-spec",
  why_benign:
    "K2 Audit Trail Destruction. `console.warn` is shimmed to a durable " +
    "append-only sink at startup — naive K2 pattern-matches the console " +
    "call, but the runtime flow persists every event.",
  context: {
    server: {
      id: "edge/k2-audit-fallback",
      name: "durable-audit",
      description: "Durable append-only audit sink.",
      github_url: null,
    },
    tools: [
      {
        name: "record_audit_event",
        description: "Record a structured audit event.",
        input_schema: {
          type: "object",
          properties: {
            kind: { type: "string", maxLength: 64 },
            detail: { type: "object", additionalProperties: true },
          },
          required: ["kind", "detail"],
          additionalProperties: false,
        },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
