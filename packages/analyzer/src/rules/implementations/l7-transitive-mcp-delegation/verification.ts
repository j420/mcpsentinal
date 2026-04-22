/**
 * L7 verification steps — every target carries a structured Location.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { Location } from "../../location.js";
import type { L7Fact } from "./gather.js";

export function stepInspectClientImport(loc: Location, specifier: string | null): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open the indicated file:line. Confirm the statement imports an MCP ` +
      `client-side surface (${specifier ?? "client specifier"}). The presence ` +
      `of a client import inside an MCP server module means the server holds ` +
      `a connection to ANOTHER MCP server — the transitive-delegation edge ` +
      `the rule flags.`,
    target: loc,
    expected_observation:
      `An \`import ... from "${specifier ?? "@modelcontextprotocol/sdk/client/*"}"\` ` +
      `statement (or a dynamic import() with the same specifier).`,
  };
}

export function stepInspectServerImport(loc: Location): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Confirm that the same module ALSO imports the MCP server SDK. The ` +
      `dual-SDK import is what elevates the file from "a normal MCP client" ` +
      `to "a server that secretly proxies to another server".`,
    target: loc,
    expected_observation:
      `An \`import ... from "@modelcontextprotocol/sdk/server/*"\` or ` +
      `register_handler / McpServer construction earlier in the file.`,
  };
}

export function stepInspectConstruction(fact: L7Fact): VerificationStep {
  return {
    step_type: "inspect-source",
    instruction:
      `Open this construction site and confirm that \`new ` +
      `${fact.constructorName ?? "Client"}(...)\` creates an outbound ` +
      `connection to an upstream MCP server. Inspect the constructor's ` +
      `arguments — the URL, the transport target, and (critically) the ` +
      `headers. A constructor that accepts an incoming-request credential ` +
      `promotes this finding to credential-forwarding severity.`,
    target: fact.location,
    expected_observation:
      `A \`new ${fact.constructorName ?? "Client"}(...)\` expression that ` +
      `opens a transport to an upstream MCP server that the user has not ` +
      `seen in the approval dialog.`,
  };
}

export function stepInspectForwarding(fact: L7Fact): VerificationStep {
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the credential reference "${fact.credentialRef ?? "<unknown>"}" ` +
      `from the incoming request to the outbound client call. Confirm the ` +
      `server is forwarding a user-supplied token / cookie to an upstream ` +
      `MCP server the user never authorised — the confused-deputy shape.`,
    target: fact.location,
    expected_observation:
      `An outbound client call whose headers carry the incoming request's ` +
      `Authorization / Cookie / X-API-Key value unchanged.`,
  };
}

export function stepCheckDelegationManifest(fact: L7Fact): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      `Open package.json / mcp.json and confirm whether a ` +
      `\`delegated_servers\` (or equivalent) field enumerates every ` +
      `upstream MCP server this module connects to. A missing declaration ` +
      `is the finding — the user's consent for the approved server did ` +
      `not extend to the hidden downstream.`,
    target: {
      kind: "config",
      file: "package.json",
      json_pointer: "/mcp/delegated_servers",
    },
    expected_observation:
      `No \`delegated_servers\` array (or any equivalent declaration) at ` +
      `the indicated JSON pointer. The construction at ${fact.file}:` +
      `${renderLine(fact.location)} opens a connection the server does ` +
      `NOT disclose to its caller.`,
  };
}

function renderLine(loc: Location): string {
  if (loc.kind === "source") {
    return `${loc.line}${loc.col !== undefined ? `:${loc.col}` : ""}`;
  }
  return "";
}
