/**
 * E2B MCP server — secure cloud sandbox for code execution.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const e2bFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/e2b",
  name: "e2b",
  why:
    "E2B MCP — sandboxed code execution frontend. Smithery-top fixtures " +
    "ship with source_code: null, so this exercises A/B/F description + " +
    "schema + annotation rules, not C1/K19 (which require source_code to " +
    "fire). The sandbox-isolation posture is documented for regulator " +
    "traceability rather than tested at the rule-fires level.",
  description:
    "E2B MCP server — spin up a disposable Linux sandbox and run a " +
    "snippet inside it. All execution is jailed to the sandbox.",
  github_url: "https://github.com/e2b-dev/mcp-server",
  tools: [
    {
      name: "create_sandbox",
      description:
        "Make a new E2B sandbox. Sandboxes are isolated Firecracker " +
        "microVMs with no access to the host.",
      input_schema: {
        type: "object",
        properties: {
          template_name: {
            type: "string",
            enum: ["base", "python", "node", "data-science"],
          },
          timeout_ms: { type: "integer", minimum: 1000, maximum: 300000 },
        },
        additionalProperties: false,
      },
    },
    {
      name: "run_snippet",
      description:
        "Execute a snippet inside an existing sandbox and return " +
        "stdout, stderr, and exit status. The snippet runs as an " +
        "unprivileged user inside the sandbox; it cannot reach the host.",
      input_schema: {
        type: "object",
        properties: {
          sandbox_id: { type: "string", pattern: "^sbx_[a-z0-9]{8,64}$" },
          language: { type: "string", enum: ["python", "node", "bash"] },
          snippet: { type: "string", maxLength: 65536 },
        },
        required: ["sandbox_id", "language", "snippet"],
        additionalProperties: false,
      },
    },
  ],
});
