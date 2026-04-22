/**
 * Shape of @modelcontextprotocol/server-puppeteer. Browser automation tools
 * for page navigation, screenshots, and basic DOM interaction.
 */
import type { BenignFixture } from "../types.js";

export const puppeteerFixture: BenignFixture = {
  id: "anthropic-official/puppeteer",
  bucket: "anthropic-official",
  why_benign:
    "Official puppeteer server. Launches Chromium, navigates to URLs, takes " +
    "screenshots. Parameters are simple URLs / selectors — no shell exec, " +
    "no template interpolation. Stresses G1 (browser IS a web-scraping " +
    "injection gateway) but the server is the harness, not the injector.",
  context: {
    server: {
      id: "anthropic/puppeteer",
      name: "puppeteer",
      description:
        "A Model Context Protocol server that provides browser automation " +
        "capabilities using Puppeteer. Enables LLMs to navigate web pages, " +
        "take screenshots and interact with DOM elements.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer",
    },
    tools: [
      {
        name: "puppeteer_goto",
        description:
          "Load the given page in the headless browser. Waits for the load " +
          "event before returning the page title.",
        input_schema: {
          type: "object",
          properties: { target_url: { type: "string", format: "uri" } },
          required: ["target_url"],
          additionalProperties: false,
        },
      },
      {
        name: "puppeteer_screenshot",
        description:
          "Take a screenshot of the current page or a specified element.",
        input_schema: {
          type: "object",
          properties: {
            name: { type: "string", maxLength: 128 },
            selector: { type: "string", maxLength: 256 },
            width: { type: "number", minimum: 100, maximum: 3840 },
            height: { type: "number", minimum: 100, maximum: 2160 },
          },
          required: ["name"],
          additionalProperties: false,
        },
      },
      {
        name: "puppeteer_click",
        description:
          "Click an element on the page identified by a CSS selector.",
        input_schema: {
          type: "object",
          properties: { selector: { type: "string", maxLength: 256 } },
          required: ["selector"],
          additionalProperties: false,
        },
      },
      {
        name: "puppeteer_fill",
        description:
          "Fill out a form input identified by a CSS selector with the " +
          "given value.",
        input_schema: {
          type: "object",
          properties: {
            selector: { type: "string", maxLength: 256 },
            value: { type: "string", maxLength: 4096 },
          },
          required: ["selector", "value"],
          additionalProperties: false,
        },
      },
      {
        name: "puppeteer_select",
        description:
          "Select an option from a dropdown by its value attribute.",
        input_schema: {
          type: "object",
          properties: {
            selector: { type: "string", maxLength: 256 },
            value: { type: "string", maxLength: 256 },
          },
          required: ["selector", "value"],
          additionalProperties: false,
        },
      },
    ],
    // Source dropped — puppeteer fixture is about the browser tool
    // surface, not the TS wrapper around it.
    source_code: null,
    dependencies: [
      {
        name: "@modelcontextprotocol/sdk",
        version: "1.5.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
      {
        name: "puppeteer",
        version: "22.15.0",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-10"),
      },
    ],
    connection_metadata: null,
  },
};
