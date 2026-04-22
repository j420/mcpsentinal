/**
 * Q7 verification-step builders.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { DxtPrivilegeSite } from "./gather.js";

export function stepInspectSite(site: DxtPrivilegeSite): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the source at the reported Location. Confirm the ` +
      `${site.kind} pattern "${site.observed}" is present: a ` +
      `${site.kind === "auto-approve-flag" ? "boolean true assigned to a trust-elevating key" :
         site.kind === "native-messaging-bridge" ? "browser-extension → MCP bridge" :
         "Electron ipcMain handler wired to a tool flow"}.`,
    target: site.location,
    expected_observation:
      `The expression elevates ${site.marker} without any user ` +
      `confirmation gate — the full privilege chain is trusted by ` +
      `default.`,
  };
}

export function stepCheckCveContext(site: DxtPrivilegeSite): VerificationStep {
  return {
    step_type: "check-dependency",
    instruction:
      `Cross-reference this pattern against CVE-2025-54135 / 54136 / ` +
      `59536 — the three disclosed DXT / MCP config-auto-approve ` +
      `vulnerabilities. Confirm the server bundled or referenced any ` +
      `of the patterns named in those advisories.`,
    target: site.location,
    expected_observation:
      `The server exhibits the same ingress shape the CVEs describe; ` +
      `deploy a mitigating client that requires per-tool user ` +
      `confirmation.`,
  };
}
