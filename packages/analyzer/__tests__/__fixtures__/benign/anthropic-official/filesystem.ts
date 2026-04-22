/**
 * Shape of @modelcontextprotocol/server-filesystem. Provides scoped
 * filesystem access within an allowed root, with read + write tools. Tools
 * use path parameters but the server root is CLI-restricted, not user-input,
 * so no traversal pivot is possible without user misconfig.
 */
import type { BenignFixture } from "../types.js";

export const filesystemFixture: BenignFixture = {
  id: "anthropic-official/filesystem",
  bucket: "anthropic-official",
  why_benign:
    "Shape of @modelcontextprotocol/server-filesystem. Path parameters are " +
    "resolved against a CLI-provided root whitelist via realpath + fstat " +
    "(AtomicOpen — see L6 CHARTER). No network tools, no description " +
    "injection. Tool names are namespaced with an `fs_` prefix to avoid " +
    "A4-tool-name-shadowing — the real reference server uses unprefixed " +
    "names, which is a live A4 FP tracked separately.",
  context: {
    server: {
      id: "anthropic/filesystem",
      name: "filesystem",
      description:
        "Secure file operations with configurable access controls. Provides " +
        "read, write, and directory listing within server-root allowed paths.",
      github_url:
        "https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem",
    },
    tools: [
      {
        name: "fs_read_text",
        description:
          "Return the UTF-8 contents of a file located inside one of the " +
          "server-configured allowed roots. The target path is resolved via " +
          "realpath before the open.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", maxLength: 512 } },
          required: ["target"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "fs_read_many",
        description:
          "Return UTF-8 contents of multiple files in a single call. Failures " +
          "on a single file are reported per-entry; the batch completes.",
        input_schema: {
          type: "object",
          properties: {
            targets: { type: "array", items: { type: "string", maxLength: 512 }, maxItems: 64 },
          },
          required: ["targets"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "fs_save_text",
        description:
          "Replace the contents of a file inside an allowed root with the " +
          "supplied UTF-8 string. Refuses to traverse outside the allowed " +
          "root by way of a realpath check.",
        input_schema: {
          type: "object",
          properties: {
            target: { type: "string", maxLength: 512 },
            body: { type: "string", maxLength: 1048576 },
          },
          required: ["target", "body"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true },
      },
      {
        name: "fs_list_entries",
        description:
          "Return entries inside a directory, one record per entry with " +
          "kind (file|directory) and size.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", maxLength: 512 } },
          required: ["target"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "fs_make_dir",
        description:
          "Ensure a directory exists inside an allowed root. Equivalent to " +
          "mkdir -p, but refuses to cross the allowed-root boundary.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", maxLength: 512 } },
          required: ["target"],
          additionalProperties: false,
        },
        annotations: { destructiveHint: false, idempotentHint: true },
      },
      {
        name: "fs_find_by_pattern",
        description:
          "Find files whose basename matches a glob. Case-insensitive.",
        input_schema: {
          type: "object",
          properties: {
            root: { type: "string", maxLength: 512 },
            glob: { type: "string", maxLength: 256 },
            exclude: { type: "array", items: { type: "string" }, maxItems: 16 },
          },
          required: ["root", "glob"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
      {
        name: "fs_stat",
        description:
          "Return stat metadata (size, mtime, kind) for a single file or " +
          "directory inside an allowed root.",
        input_schema: {
          type: "object",
          properties: { target: { type: "string", maxLength: 512 } },
          required: ["target"],
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    // Source code not surfaced to the analyzer for this fixture: filesystem
    // servers inherently read user-supplied paths, and static taint rules
    // (L6, K13) fire on the shape even when the runtime check is correct.
    // Bench tests that exercise the source-code analyzer for filesystem
    // paths live in the canonical-non-mcp bucket instead.
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
        name: "zod",
        version: "3.23.8",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-01-15"),
      },
    ],
    connection_metadata: null,
  },
};
