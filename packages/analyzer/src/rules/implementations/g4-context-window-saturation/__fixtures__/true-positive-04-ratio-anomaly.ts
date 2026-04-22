/**
 * TP-04: Description-to-parameter ratio anomaly. One tool takes a single
 * `query` parameter but the description is ~8 kB — ratio ~8000 bytes/param,
 * well above the 2000 threshold. Length alone + ratio alone both fire.
 * Padding is lorem-ipsum style prose with enough lexical variety to
 * avoid the repetition signal — so this fixture isolates the ratio
 * signal from the repetition signal.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  const sentences = [
    "The filesystem underpins every durable operation this service attempts.",
    "Buffered writes coalesce into larger sequential I/O where possible.",
    "Readers observe a consistent snapshot thanks to copy-on-write segments.",
    "Background compaction merges adjacent segments to reclaim deleted space.",
    "Error handling distinguishes transient faults from irrecoverable corruption.",
  ];
  const blocks: string[] = [];
  // Build ~8 kB from varied sentences (avoids repetition signature).
  for (let i = 0; i < 80; i++) {
    blocks.push(sentences[i % sentences.length] + " ");
  }
  const description = blocks.join("");

  const siblingDescription = "Returns diagnostic info.";
  return {
    server: {
      id: "g4-tp04",
      name: "tp04-ratio-anomaly",
      description: null,
      github_url: null,
    },
    tools: [
      {
        name: "query_store",
        description,
        input_schema: {
          type: "object",
          properties: { query: { type: "string" } },
        },
      },
      { name: "t1", description: siblingDescription, input_schema: null },
      { name: "t2", description: siblingDescription, input_schema: null },
      { name: "t3", description: siblingDescription, input_schema: null },
      { name: "t4", description: siblingDescription, input_schema: null },
      { name: "t5", description: siblingDescription, input_schema: null },
    ],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
  };
}
