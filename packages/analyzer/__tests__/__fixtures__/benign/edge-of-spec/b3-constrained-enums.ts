/**
 * Stresses B3 Excessive Parameter Count. 16 parameters crosses the >15
 * threshold, but every parameter is a well-constrained enum or integer
 * with tight bounds. The intent is a structured filter surface, not a
 * bloat marker. At worst an informational notice; no critical/high.
 */
import type { BenignFixture } from "../types.js";

export const b3ConstrainedEnumsFixture: BenignFixture = {
  id: "edge-of-spec/b3-constrained-enums",
  bucket: "edge-of-spec",
  why_benign:
    "B3 threshold is >15 params; this tool has exactly 16, every one is a " +
    "narrow enum or bounded int — legitimate rich filter surface.",
  context: {
    server: {
      id: "edge/b3-enums",
      name: "issue-filter",
      description: "Issue-tracker filter builder.",
      github_url: null,
    },
    tools: [
      {
        name: "search_issues",
        description:
          "Search project issues using structured filters. Each argument " +
          "is a narrow enum or a small integer range.",
        input_schema: {
          type: "object",
          properties: {
            status: { type: "string", enum: ["open", "closed"] },
            priority: { type: "string", enum: ["p0", "p1", "p2", "p3"] },
            label_a: { type: "string", enum: ["bug", "feature", "docs"] },
            label_b: { type: "string", enum: ["ui", "api", "backend"] },
            label_c: { type: "string", enum: ["small", "medium", "large"] },
            sort: { type: "string", enum: ["created", "updated", "priority"] },
            order: { type: "string", enum: ["asc", "desc"] },
            per_page: { type: "integer", minimum: 1, maximum: 100 },
            page: { type: "integer", minimum: 1, maximum: 1000 },
            assignee_kind: { type: "string", enum: ["me", "any", "none"] },
            reporter_kind: { type: "string", enum: ["me", "any", "none"] },
            milestone_kind: { type: "string", enum: ["any", "none"] },
            reaction: { type: "string", enum: ["any", "none"] },
            age_bucket: { type: "string", enum: ["day", "week", "month"] },
            region: { type: "string", enum: ["us", "eu", "apac"] },
            project_ring: { type: "string", enum: ["inner", "outer"] },
          },
          required: [],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
  allowed_findings: [
    {
      rule_id: "B3",
      severity: "low",
      reason: "B3 threshold is informational; 16 constrained enums is benign.",
    },
  ],
};
