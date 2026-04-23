/**
 * Stresses O-category env harvesting. Reading `process.env.HOME` is a
 * normal thing every shell program does — it is not a data-exfil
 * signal. Rules that flag "reads process.env" broadly will FP here;
 * a correct rule considers the specific env var name.
 */
import type { BenignFixture } from "../types.js";

const sourceCode = `import path from "node:path";

/** Return the conventional config directory for the current user. */
export function configDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? "/tmp";
  return path.join(home, ".config", "edge-o5");
}
`;

export const o5NonSensitiveEnvFixture: BenignFixture = {
  id: "edge-of-spec/o5-non-sensitive-env",
  bucket: "edge-of-spec",
  why_benign:
    "O-category env harvesting. `process.env.HOME` / `USERPROFILE` are " +
    "non-sensitive user-path discovery, not credential harvesting.",
  context: {
    server: {
      id: "edge/o5-env",
      name: "config-path-helper",
      description: "Returns conventional user config directory.",
      github_url: null,
    },
    tools: [
      {
        name: "config_dir",
        description: "Return the conventional config dir for the current user.",
        input_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
        annotations: { readOnlyHint: true, destructiveHint: false },
      },
    ],
    source_code: sourceCode,
    dependencies: [],
    connection_metadata: null,
  },
};
