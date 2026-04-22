/**
 * Stresses A8 Description-Capability Mismatch. The description says
 * "read-only analytics dashboard", and all parameters are query-shaped
 * (filter, group_by, interval) — genuinely read-only. A naive matcher
 * that flags any tool claiming "read-only" for inspection would
 * false-positive; A8 must verify there are no destructive parameters.
 */
import type { BenignFixture } from "../types.js";

export const a8AnalyticsDashboardFixture: BenignFixture = {
  id: "edge-of-spec/a8-analytics-dashboard",
  bucket: "edge-of-spec",
  why_benign:
    "A8 Description-Capability Mismatch. 'Read-only' claim plus strictly " +
    "query parameters (filter/group_by/interval) — actually read-only.",
  context: {
    server: {
      id: "edge/a8-analytics",
      name: "analytics-dashboard",
      description: "Read-only analytics query interface.",
      github_url: null,
    },
    tools: [
      {
        name: "query_events",
        description:
          "Read-only analytics dashboard: aggregate product events over a " +
          "time window. Returns bucketed counts. No mutation.",
        input_schema: {
          type: "object",
          properties: {
            filter: { type: "string", maxLength: 512 },
            group_by: { type: "string", enum: ["user", "country", "plan"] },
            interval: { type: "string", enum: ["hour", "day", "week"] },
            start: { type: "string", format: "date-time" },
            end: { type: "string", format: "date-time" },
          },
          required: ["start", "end"],
          additionalProperties: false,
        },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  },
};
