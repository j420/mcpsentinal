/**
 * Vercel MCP server — deploy and inspect Vercel projects.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const vercelFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/vercel",
  name: "vercel",
  why:
    "Vercel MCP. Stresses A2 excessive-scope negative (description " +
    "lists concrete actions, not 'unrestricted access'), and F2 " +
    "capability profile negative.",
  description:
    "Vercel MCP server — enumerate projects and deployments and read " +
    "build artifacts for the authenticated Vercel account.",
  github_url: "https://github.com/vercel/mcp-server",
  tools: [
    {
      name: "enum_projects",
      description:
        "Enumerate projects in the Vercel account accessible to the token.",
      input_schema: {
        type: "object",
        properties: {
          team_id: { type: "string", maxLength: 64 },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "enum_deployments",
      description:
        "Enumerate the most recent deployments for a project, " +
        "optionally filtered by target (production or preview).",
      input_schema: {
        type: "object",
        properties: {
          project_id: { type: "string", maxLength: 64 },
          deploy_target: {
            type: "string",
            enum: ["production", "preview"],
          },
          limit: { type: "integer", minimum: 1, maximum: 100 },
        },
        required: ["project_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "fetch_build_artifact",
      description:
        "Retrieve build output for a specific deployment. The body is " +
        "capped at 1MB to stay within response limits.",
      input_schema: {
        type: "object",
        properties: {
          deployment_id: { type: "string", maxLength: 128 },
        },
        required: ["deployment_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
