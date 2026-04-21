/**
 * G7 verification-step builders. Each step carries a structured
 * `target: Location` (v2 standard §4).
 *
 * Zero regex, zero long string arrays.
 */

import type { VerificationStep } from "../../../evidence.js";
import type { G7Fact } from "./gather.js";

export function stepInspectDnsSink(fact: G7Fact): VerificationStep {
  const sinkName = "name" in fact.sink ? fact.sink.name : (fact.sink as { token: string }).token;
  return {
    step_type: "inspect-source",
    instruction:
      `Open the file at this position and confirm the call is \`${sinkName}\` ` +
      `(${fact.sink.description}) and its hostname argument is constructed ` +
      `dynamically — template literal, concatenation, identifier reference, or ` +
      `wrapper call. Safe equivalents (a hardcoded hostname, a static allowlist ` +
      `lookup returning a constant string) would have caused the gather step to ` +
      `skip this call.`,
    target: fact.sinkLocation,
    expected_observation:
      `A ${sinkName}(...) call whose first argument is a dynamic expression carrying ` +
      `data that an authoritative nameserver operator would observe.`,
  };
}

export function stepInspectHostnameConstruction(fact: G7Fact): VerificationStep {
  const hopCount = fact.dynamicHops.length;
  const hopSummary = fact.dynamicHops
    .slice(0, 4)
    .map((h) => `${h.kind}@${renderLoc(h.location)} (${h.observed.slice(0, 40)})`)
    .join(" → ");
  return {
    step_type: "trace-flow",
    instruction:
      `Trace the ${hopCount} dynamic hop(s) of the hostname construction: ${hopSummary}. ` +
      `Confirm each hop is a real data-flow step and that the dynamic portion ultimately ` +
      `derives from application data (env var, user parameter, database row, file read). ` +
      `A broken hop invalidates the chain.`,
    target: fact.hostnameLocation,
    expected_observation:
      `${hopCount} dynamic hop(s) ending in a reference to a value that a reviewer would ` +
      `classify as sensitive — including non-obvious cases like session identifiers or user IDs.`,
  };
}

export function stepCheckEncodingWrappers(fact: G7Fact): VerificationStep {
  if (fact.encodingWrappers.length === 0) {
    return {
      step_type: "inspect-source",
      instruction:
        `No encoding wrapper (Buffer.from / btoa / base64.b64encode / crypto.createHash / ` +
        `.toString("hex")) was observed on the hostname construction path. The dynamic data ` +
        `is passed into the subdomain in its raw form. Confirm the raw data is URL/DNS-safe ` +
        `(alphanumeric + hyphens only) — if not, the DNS query will fail at runtime, which is ` +
        `evidence the code path is not exercised benignly.`,
      target: fact.hostnameLocation,
      expected_observation:
        `No encoding step. Raw data is interpolated into the DNS subdomain.`,
    };
  }
  const names = fact.encodingWrappers.map((w) => w.name).join(", ");
  return {
    step_type: "inspect-source",
    instruction:
      `Encoding wrappers detected on the hostname path: ${names}. Confirm the encoding ` +
      `choice (base64 / hex / URL-escape / hash) produces a DNS-label-safe character set ` +
      `and estimate the entropy of the resulting subdomain. High entropy (>5.5 bits/char) ` +
      `is a strong indicator of deliberate exfil vs legitimate service discovery.`,
    target: fact.hostnameLocation,
    expected_observation:
      `Encoded subdomain segment — the attacker intentionally prepared the data for DNS ` +
      `transport.`,
  };
}

export function stepInspectAllowlist(fact: G7Fact): VerificationStep {
  if (fact.allowlist && fact.allowlistLocation) {
    return {
      step_type: "inspect-source",
      instruction:
        `A hostname allowlist primitive \`${fact.allowlist.name}\` was observed in the ` +
        `enclosing function scope. Confirm the check ACTUALLY runs on the dynamic hostname ` +
        `above — an allowlist call on a DIFFERENT hostname expression does not neutralise ` +
        `this flow. Also confirm the allowlist is not itself populated from untrusted input.`,
      target: fact.allowlistLocation,
      expected_observation:
        `The allowlist primitive runs on the same hostname variable that flows to the DNS ` +
        `sink.`,
    };
  }
  return {
    step_type: "inspect-source",
    instruction:
      `No hostname allowlist (isAllowedHost / validateHostname / assertAllowlistedHost / ` +
      `ALLOWED_HOSTS.includes) was observed in the enclosing function scope. Confirm by ` +
      `scanning the surrounding ~30 lines of the same function. If a legitimate allowlist ` +
      `IS present but uses different identifiers, extend the marker list in data/config.ts.`,
    target: fact.sinkLocation,
    expected_observation:
      `No hostname allowlist in scope — the DNS sink is reachable with an attacker-controlled ` +
      `subdomain.`,
  };
}

export function stepCheckDnsEgressPolicy(): VerificationStep {
  return {
    step_type: "check-config",
    instruction:
      "Verify the deployment environment's DNS egress controls: (1) Is DNS traffic filtered " +
      "to an allowlist of approved resolvers (Cloudflare Gateway, Unbound local resolver " +
      "with blocklist, AWS Route 53 Resolver DNS Firewall)? (2) Are DNS query logs " +
      "monitored for high-entropy subdomain labels? (3) Are egress UDP/53 / TCP/53 " +
      "connections restricted to known resolver IPs? Even a real DNS sink is partially " +
      "neutralised if the resolver refuses to recurse on attacker domains.",
    target: {
      kind: "config",
      file: "deployment/network-policy",
      json_pointer: "/dns-egress",
    },
    expected_observation:
      "Confirmation whether DNS egress is constrained. If not, the sink is directly exploitable.",
  };
}

function renderLoc(loc: { kind: string } & Record<string, unknown>): string {
  if (loc.kind === "source") {
    return `${loc.file}:${loc.line}${loc.col !== undefined ? `:${loc.col}` : ""}`;
  }
  return loc.kind;
}
