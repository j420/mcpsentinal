/**
 * Stresses P7 (Linux capability constraint). A docker run invocation
 * captured in a deploy snippet uses `--cap-drop=ALL --cap-add=
 * NET_BIND_SERVICE`. P7 fires on capability bloat (e.g. --privileged,
 * --cap-add=SYS_ADMIN); drop-all + narrow-add is the compliant shape.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `#!/usr/bin/env bash
# deploy.sh — run service with minimal Linux capabilities.
set -euo pipefail

docker run --rm \\
  --cap-drop=ALL \\
  --cap-add=NET_BIND_SERVICE \\
  --read-only \\
  --tmpfs /tmp:rw,size=16m,mode=1777 \\
  --user 1001:1001 \\
  --name edge-p7 \\
  edge-p7:latest
`;

export const p7CapConstrainedFixture: BenignFixture = {
  id: "edge-of-spec/p7-cap-constrained",
  bucket: "edge-of-spec",
  why_benign:
    "P7 Linux capability constraint. `--cap-drop=ALL --cap-add=NET_BIND_" +
    "SERVICE` is the least-privilege shape, not a bloated cap set.",
  context: {
    server: {
      id: "edge/p7-caps",
      name: "least-priv-service",
      description: "Service run with strictly constrained capabilities.",
      github_url: null,
    },
    tools: [],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
