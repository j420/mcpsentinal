/**
 * H2 TN-03 — Short non-semver server version ("2.0") must NOT fire.
 *
 * Behaviour locked by this fixture:
 *   - server_version = "2.0"              (two-digit numeric, non-semver)
 *   - server_instructions = null          (no instructions field)
 *   - server.name is a plain benign identifier
 *
 * Regression this fixture guards against: wave-5 integration surfaced a
 * false positive where the version-shape detector flagged short numeric
 * strings (e.g. "2.0", "0.1") as "anomalous". The fix was committed in
 * 79ea5c9 ("chore(phase-1,wave-5): ... fix H2 version-shape FP"). A
 * regression here would re-introduce the FP silently — this TN fixture
 * makes the expectation behavioural instead of relying on the census.
 */
import type { AnalysisContext } from "../../../../engine.js";

export function buildContext(): AnalysisContext {
  return {
    server: {
      id: "h2-tn03",
      name: "mcp-benign",
      description: null,
      github_url: null,
    },
    tools: [],
    source_code: null,
    dependencies: [],
    connection_metadata: null,
    initialize_metadata: {
      server_version: "2.0",
      server_instructions: null,
    },
  };
}
