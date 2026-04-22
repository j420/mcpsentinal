/**
 * TP-02: Peer z-score outlier. One tool has a ~4 kB description while
 * 15 sibling tools have uniform ~80-byte descriptions — the outlier is
 * many standard deviations above the peer mean.
 *
 * With 16 tools, 15 of them ~80 bytes, one at ~4000 bytes:
 *   mean ≈ 325, population stddev ≈ 942,
 *   z-score of outlier ≈ (4000 - 325) / 942 ≈ 3.9
 * → exceeds the 3.0 threshold.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  // Deliberately varied sentences so unique-line ratio does not fire; the
  // isolated signal should be the peer z-score outlier. Build ~4000 bytes.
  const pieces = [
    "Long-form description of tool behaviour at the system boundary.",
    "Covers error semantics, retry cadence, and how cancellations propagate.",
    "Includes examples for typical and pathological inputs with stable IDs.",
    "Notes on concurrency: the tool is safe to call in parallel within limits.",
    "Operational SLOs and their measurement windows are documented inline.",
  ];
  const blocks: string[] = [];
  for (let i = 0; i < 55; i++) blocks.push(pieces[i % pieces.length] + " ");
  const longDescription = blocks.join("");

  const siblings: Array<{
    name: string;
    description: string;
    input_schema: null;
  }> = [];
  const siblingWriteups = [
    "Adds two integers.",
    "Returns the current time.",
    "Pings the server.",
    "Fetches the version string.",
    "Returns uptime seconds.",
    "Returns whether the service is ready.",
    "Returns whether the service is live.",
    "Echoes the argument back.",
    "Lists registered capabilities.",
    "Returns the supported MCP versions.",
    "Returns the active region.",
    "Returns the host OS name.",
    "Returns the process ID.",
    "Returns the configured log level.",
    "Returns the build commit hash.",
  ];
  for (let i = 0; i < siblingWriteups.length; i++) {
    siblings.push({
      name: `t${i}`,
      description: siblingWriteups[i],
      input_schema: null,
    });
  }

  return {
    server: {
      id: "g4-tp02",
      name: "tp02-zscore-outlier",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "bloated",
        description: longDescription,
        input_schema: {
          type: "object",
          properties: { arg: { type: "string" } },
        },
      },
      ...siblings,
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
