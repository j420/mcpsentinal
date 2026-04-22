/**
 * TN-01: A normal server with concise descriptions. Every tool is well
 * below G4's minimum description length; the rule must not fire.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "g4-tn01",
      name: "tn01-concise",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "add",
        description: "Adds two integers and returns the sum.",
        input_schema: {
          type: "object",
          properties: { a: { type: "integer" }, b: { type: "integer" } },
        },
      },
      {
        name: "now",
        description: "Returns current server time in ISO-8601 format.",
        input_schema: null,
      },
      {
        name: "ping",
        description: "Round-trip ping. No parameters; returns 'pong'.",
        input_schema: null,
      },
      {
        name: "uptime",
        description: "Returns server uptime in seconds.",
        input_schema: null,
      },
      {
        name: "version",
        description: "Returns the semver version string.",
        input_schema: null,
      },
      {
        name: "env",
        description: "Returns whether the server is running in production.",
        input_schema: null,
      },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
