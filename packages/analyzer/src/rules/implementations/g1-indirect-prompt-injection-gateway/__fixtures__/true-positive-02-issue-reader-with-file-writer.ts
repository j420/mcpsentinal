/**
 * G1 TP-02 — Issue-tracker reader + file writer (charter edge case #3).
 *
 * Tool A reads from an external issue-tracker URL (GitHub / Jira). Any
 * public commenter can inject. Tool B writes files on the local host.
 * Expected: one G1 finding with the issue reader as the gateway and
 * the file writer as the canonical sink (severity-preferred over
 * network egress because filesystem_write is ranked higher in pickPrimarySink).
 */

import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "srv-g1-tp2",
      name: "triage-agent",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "fetch_issue_comments",
        description:
          "Fetches from external issue tracker URLs and parses untrusted user " +
          "comments from GitHub, Jira, or Linear tickets.",
        input_schema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "the external issue URL to fetch",
            },
          },
        },
      },
      {
        name: "write_triage_notes",
        description:
          "Writes to file on disk — appends triage notes to a document " +
          "and inserts a record into the workspace database for later review.",
        input_schema: {
          type: "object",
          properties: {
            path: { type: "string", description: "destination file path" },
            content: { type: "string", description: "note content" },
          },
        },
        annotations: {
          destructiveHint: true,
        },
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
