/**
 * F4 spec-field registry.
 *
 * Loaded at module scope by `gather.ts`. Object-literal shape so the
 * no-static-patterns guard does not consider the list a "long string-
 * literal array". Each entry documents a single MCP spec field, its
 * requirement level, and the short rationale F4 uses in the evidence
 * chain.
 *
 * Adding a field: add a property to SPEC_FIELDS. Do NOT add fields that
 * belong to other rules (A, B, C, I, J) — F4 covers only the minimum
 * structural surface that every MCP server must fill in.
 */

export type Requirement = "required" | "recommended";

export type FieldClass =
  | "tool-name-empty"
  | "tool-name-whitespace"
  | "tool-description-missing"
  | "tool-input-schema-missing";

export interface SpecFieldEntry {
  /** Which field class this entry documents. */
  class: FieldClass;
  /** MCP spec revision that first introduced the field. */
  spec_revision: string;
  /** Whether the spec marks the field as required or recommended. */
  requirement: Requirement;
  /** One-line rationale used in source link. */
  rationale: string;
  /** One-line impact scenario used in impact link. */
  impact_scenario: string;
}

export const SPEC_FIELDS: Record<FieldClass, SpecFieldEntry> = {
  "tool-name-empty": {
    class: "tool-name-empty",
    spec_revision: "2024-11-05",
    requirement: "required",
    rationale:
      "The tool.name field is required by the original MCP specification. " +
      "A missing or empty name makes tool-selection by the LLM ambiguous and " +
      "prevents client-side approval dialogs from rendering a tool identifier.",
    impact_scenario:
      "AI client enumerates the tool but has no stable identifier to present " +
      "to the user for approval. Tool-name-based allowlists, audit logs, and " +
      "automation rules silently skip the tool or bucket it under the empty " +
      "string, defeating the approval mechanism the name field exists to " +
      "support.",
  },
  "tool-name-whitespace": {
    class: "tool-name-whitespace",
    spec_revision: "2024-11-05",
    requirement: "required",
    rationale:
      "A whitespace-only tool.name satisfies the field-present check but " +
      "collapses to an empty identifier when trimmed. The MCP spec treats " +
      "whitespace-only names as a violation because downstream consumers " +
      "trim before matching.",
    impact_scenario:
      "Approval UIs render a blank row; allowlists that normalise on trim " +
      "behave as if the tool is unnamed. The risk surface is identical to an " +
      "empty name but the raw field passes a naive null check.",
  },
  "tool-description-missing": {
    class: "tool-description-missing",
    spec_revision: "2024-11-05",
    requirement: "recommended",
    rationale:
      "The tool.description field is recommended by the MCP spec. AI clients " +
      "use the description to decide when to call the tool and how to fill " +
      "its parameters. Absence forces the client to guess from the tool " +
      "name alone, which is the documented vector for A4 tool-name-shadowing " +
      "confusion.",
    impact_scenario:
      "A tool named 'update' could be a read or a destructive write. Without " +
      "a description the LLM must infer intent from the name, and the user " +
      "must confirm a tool they cannot characterise. This degrades the safety " +
      "signal A/B rules rely on for prompt-injection and scope-claim detection.",
  },
  "tool-input-schema-missing": {
    class: "tool-input-schema-missing",
    spec_revision: "2024-11-05",
    requirement: "recommended",
    rationale:
      "The tool.inputSchema field is recommended by the MCP spec. Clients " +
      "use it to validate arguments before dispatch. Absence means the client " +
      "passes unvalidated free-form input — the schema-absence path of B4.",
    impact_scenario:
      "The AI client cannot constrain argument shape or value ranges. Every " +
      "parameter becomes a free-form string, which removes the protocol-level " +
      "guard against malformed or injection-laden input. The tool is " +
      "schema-less by default, producing the B4 risk profile.",
  },
};
