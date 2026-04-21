// true-negative-02: dynamic hostname, but guarded by an allowlist
// primitive. The rule still fires but with severity downgraded to
// informational.

import * as dns from "dns";

function isAllowedHost(host: string): boolean {
  const ALLOWED_SUFFIXES = [".internal.service"];
  return ALLOWED_SUFFIXES.some((s) => host.endsWith(s));
}

function resolveIfAllowed(service: string) {
  const host = `${service}.internal.service`;
  if (isAllowedHost(host)) {
    dns.resolve(host, "A", () => {});
  }
}

resolveIfAllowed("billing");
