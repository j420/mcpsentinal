/**
 * Stresses J4 Health Endpoint Information Disclosure. A `/health`
 * endpoint that returns ONLY `{ok: true}` — no versions, no OS info,
 * no env vars, no disk paths, no memory stats. J4's concern is
 * leakage; a minimal liveness probe leaks nothing.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import express from "express";

const app = express();

// Minimal liveness probe. NO version, NO env, NO OS info.
app.get("/health", (_req, res) => {
  res.json({ ok: true });
});
`;

export const j4MinimalHealthFixture: BenignFixture = {
  id: "edge-of-spec/j4-minimal-health",
  bucket: "edge-of-spec",
  why_benign:
    "J4 naive match on /health endpoint. Response payload is literally " +
    "`{ok: true}` — no OS/version/env/disk disclosure possible.",
  context: {
    server: {
      id: "edge/j4-health",
      name: "liveness-probe",
      description: "Minimal liveness probe.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [
      {
        name: "express",
        version: "4.19.2",
        has_known_cve: false,
        cve_ids: [],
        last_updated: new Date("2026-02-01"),
      },
    ],
    connection_metadata: null,
  },
};
