/**
 * C5 verification-step builders — each step carries a structured Location
 * target (Rule Standard v2 §4). Auditors walk the steps to confirm a
 * finding without re-running the scanner.
 *
 * No regex, no long string-literal arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { SecretHit } from "./gather.js";

/** Step 1 — open the file at the credential position. */
export function stepInspectCredentialPosition(hit: SecretHit): VerificationStep {
  const issuer =
    hit.spec?.issuer ??
    (hit.kind === "pem-private-key" ? "PEM private key header" : "credential-shaped assignment");
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this line and confirm the literal is a real ` +
      `${issuer} credential — not a placeholder, not a fixture, not a ` +
      `comment. If the value is a live production secret, treat the ` +
      `credential as compromised the moment this finding was generated ` +
      `(repository read access is public).`,
    target: hit.location,
    expected_observation:
      hit.kind === "pem-private-key"
        ? `A "${hit.observedLine.slice(0, 60)}" line followed by base64 payload of a PEM private key.`
        : `An assignment whose right-hand side is the literal "${hit.masked}" matching ${issuer} format.`,
  };
}

/**
 * Step 2 — check the surrounding code for a structurally-identical
 * environment variable lookup. "Is the value ALSO read from process.env?"
 * The presence of an env lookup does not clear the finding (the literal
 * is still in the repo) but changes the remediation from "rotate + move
 * to env" to "remove the fallback literal — env read is in place".
 */
export function stepCheckEnvironmentFallback(
  hit: SecretHit,
  file: string,
): VerificationStep {
  const target: Location = {
    kind: "source",
    file,
    line: 1,
    col: 1,
  };
  return {
    step_type: "inspect-source",
    instruction:
      hit.hasEnvironmentLookup
        ? `The file ALSO contains a process.env / os.environ lookup. Confirm ` +
          `whether this is a "literal fallback for local dev" pattern or a ` +
          `true hardcoded-only path. Either way, the literal is committed and ` +
          `must be rotated.`
        : `The file contains NO environment-variable read for this credential. ` +
          `Confirm there is no sibling config file (.env, settings.py, config.ts) ` +
          `that loads the secret structurally — if there isn't, the finding is ` +
          `a pure hardcoded credential with no runtime override.`,
    target,
    expected_observation:
      hit.hasEnvironmentLookup
        ? "A process.env or os.environ read in the same module — a fallback literal pattern."
        : "No process.env / os.environ read in the same module — the literal is the ONLY source of the credential at runtime.",
  };
}

/** Step 3 — placeholder / example-file corroboration (cleared findings skip this). */
export function stepVerifyNotPlaceholder(hit: SecretHit): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Re-read the line and confirm no placeholder marker is present. If the ` +
      `value truly contains one of: REPLACE / PLACEHOLDER / xxxxx / your_*_here / ` +
      `example / sample / dummy — DISMISS the finding. The ` +
      `charter requires placeholders to suppress the critical severity because ` +
      `example credentials in .env.example files are intentional, not a leak.`,
    target: hit.location,
    expected_observation:
      `The credential value contains none of the placeholder markers AND the ` +
      `filename is not on the example-file list (.env.example / .env.sample / ` +
      `.env.template). Only then is the finding an actual leaked secret.`,
  };
}
