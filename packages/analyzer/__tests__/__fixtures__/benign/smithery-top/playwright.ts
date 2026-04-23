/**
 * Playwright MCP server — local browser automation for test workflows.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const playwrightFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/playwright",
  name: "playwright",
  why:
    "Playwright MCP. Stresses E4 excessive-tool-count negative (4 " +
    "tools, well under 50), and I4 dangerous-resource-URI negative " +
    "(no resource surface).",
  description:
    "Playwright MCP server — drive a local Chromium, Firefox, or WebKit " +
    "binary for test automation. Runs the browsers under a pinned " +
    "browser binary that Playwright manages.",
  github_url: "https://github.com/microsoft/playwright-mcp",
  tools: [
    {
      name: "open_browser",
      description: "Launch a browser and return a session id.",
      input_schema: {
        type: "object",
        properties: {
          engine: {
            type: "string",
            enum: ["chromium", "firefox", "webkit"],
          },
          headless: { type: "boolean" },
        },
        additionalProperties: false,
      },
    },
    {
      name: "step_to_target",
      description: "Step the session to an https target page.",
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
      name: "press_element",
      description: "Press an element matching a Playwright selector.",
      input_schema: {
        type: "object",
        properties: {
          session_id: { type: "string", maxLength: 128 },
          selector: { type: "string", maxLength: 1024 },
        },
        required: ["session_id", "selector"],
        additionalProperties: false,
      },
    },
    {
      name: "capture_image",
      description: "Take a PNG image of the current viewport.",
      input_schema: {
        type: "object",
        properties: {
          session_id: { type: "string", maxLength: 128 },
        },
        required: ["session_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true },
    },
  ],
});
