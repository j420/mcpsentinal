/**
 * Browserbase MCP server — cloud headless browser automation.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const browserbaseFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/browserbase",
  name: "browserbase",
  why:
    "Browserbase MCP. Stresses I4 dangerous-resource-URI negative " +
    "(no resource surface), and I11 over-privileged-root negative.",
  description:
    "Browserbase MCP server — drive a cloud headless browser session " +
    "(step, press, capture image) against a Browserbase project.",
  github_url: "https://github.com/browserbase/mcp-server-browserbase",
  tools: [
    {
      name: "open_session",
      description:
        "Make a new browser session and return its id. The session " +
        "auto-expires after 10 minutes of inactivity.",
      input_schema: {
        type: "object",
        properties: {
          project_id: { type: "string", pattern: "^[a-z0-9-]{8,64}$" },
          user_agent: { type: "string", maxLength: 256 },
        },
        required: ["project_id"],
        additionalProperties: false,
      },
    },
    {
      name: "step_page",
      description:
        "Step the session's browser to an https target. The target " +
        "must be an https scheme.",
      input_schema: {
        type: "object",
        properties: {
          session_id: { type: "string", maxLength: 128 },
          target_https: {
            type: "string",
            format: "uri",
            maxLength: 2048,
            pattern: "^https://",
          },
        },
        required: ["session_id", "target_https"],
        additionalProperties: false,
      },
    },
    {
      name: "capture_image",
      description:
        "Take a PNG image of the current page and return it as a " +
        "base64 payload in the response.",
      input_schema: {
        type: "object",
        properties: {
          session_id: { type: "string", maxLength: 128 },
          full_page: { type: "boolean" },
        },
        required: ["session_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
    },
  ],
});
