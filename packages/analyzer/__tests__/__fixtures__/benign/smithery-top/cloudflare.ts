/**
 * Shape of the Cloudflare MCP server — manage DNS zones, Workers, and
 * KV via the Cloudflare REST API.
 */
import type { BenignFixture } from "../types.js";
import { makeSmitheryFixture } from "./_helpers.js";

export const cloudflareFixture: BenignFixture = makeSmitheryFixture({
  id: "smithery-top/cloudflare",
  name: "cloudflare",
  why:
    "Cloudflare MCP. Stresses B3 parameter-count negative (3-5 per " +
    "tool), B4 schema-less negative (every tool has a schema), and " +
    "F5 namespace-squatting negative (Cloudflare upstream brand).",
  description:
    "Cloudflare MCP server — manage DNS records, ship Workers, and " +
    "read/write Workers KV namespaces via the Cloudflare v4 REST API.",
  github_url: "https://github.com/cloudflare/mcp-server-cloudflare",
  tools: [
    {
      name: "list_dns_records",
      description:
        "List DNS records for a zone the API token has access to.",
      input_schema: {
        type: "object",
        properties: {
          zone_id: { type: "string", pattern: "^[a-f0-9]{32}$" },
          record_type: {
            type: "string",
            enum: ["A", "AAAA", "CNAME", "MX", "TXT", "NS"],
          },
        },
        required: ["zone_id"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
    {
      name: "ship_worker",
      description:
        "Upload a Workers script to a named route. Requires the token " +
        "to have Workers:Edit on the account.",
      input_schema: {
        type: "object",
        properties: {
          account_id: { type: "string", pattern: "^[a-f0-9]{32}$" },
          worker_name: { type: "string", maxLength: 63 },
          script_source: { type: "string", maxLength: 1048576 },
        },
        required: ["account_id", "worker_name", "script_source"],
        additionalProperties: false,
      },
    },
    {
      name: "kv_read_one",
      description: "Read a single entry from a Workers KV namespace.",
      input_schema: {
        type: "object",
        properties: {
          account_id: { type: "string", maxLength: 64 },
          namespace_id: { type: "string", maxLength: 64 },
          entry_key: { type: "string", maxLength: 512 },
        },
        required: ["account_id", "namespace_id", "entry_key"],
        additionalProperties: false,
      },
      annotations: { readOnlyHint: true, idempotentHint: true },
    },
  ],
});
