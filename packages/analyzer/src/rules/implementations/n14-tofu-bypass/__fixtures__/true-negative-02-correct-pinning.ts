import type { AnalysisContext } from "../../../../engine.js";

const SOURCE = [
  "// @ts-nocheck",
  "// TOFU-aware code that rejects mismatches properly",
  "import { known_hosts } from './hosts';",
  "export function verify(peer: string, fp: string) {",
  "  const pinned = known_hosts.get(peer);",
  "  if (!pinned) throw new Error('require operator confirmation');",
  "  if (pinned !== fp) throw new Error('fingerprint mismatch — reject');",
  "  return true;",
  "}",
].join("\n");

export function buildContext(): AnalysisContext {
  return {
    server: { id: "srv-n14-tn2", name: "s", description: null, github_url: null },
    tools: [],
    source_code: SOURCE,
    dependencies: [],
    connection_metadata: null,
  };
}
