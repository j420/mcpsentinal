/**
 * G7 — DNS-Based Data Exfiltration Channel: rule-specific config.
 *
 * Lives under `data/` so the no-static-patterns guard skips the
 * directory. Every matcher is name-equality or substring-includes —
 * zero regex.
 */

// ─── DNS-resolution sinks ────────────────────────────────────────────────

/**
 * Canonical DNS-resolution sinks. The AST walker fires when a call's
 * callee name matches one of these entries AND the hostname argument
 * is dynamically constructed.
 */
export interface DnsSink {
  readonly name: string;
  readonly shape: "qualified-function" | "bare-function";
  readonly hostnameArgIdx: number;
  readonly ecosystem: "node" | "python" | "agnostic";
  readonly description: string;
}

export const G7_DNS_SINKS: readonly DnsSink[] = [
  { name: "dns.resolve", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolve() — canonical A-record resolution" },
  { name: "dns.resolve4", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolve4() — IPv4 A-record resolution" },
  { name: "dns.resolve6", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolve6() — IPv6 AAAA-record resolution" },
  { name: "dns.resolveTxt", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolveTxt() — TXT record exfil variant" },
  { name: "dns.resolveCname", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolveCname() — CNAME exfil variant" },
  { name: "dns.resolveMx", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolveMx() — MX record exfil variant" },
  { name: "dns.resolveNs", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolveNs() — NS record variant" },
  { name: "dns.resolveSrv", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns resolveSrv() — SRV record variant" },
  { name: "dns.lookup", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns lookup() — getaddrinfo wrapper, the classic exfil sink" },
  { name: "dnsPromises.resolve", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns promises API — same resolve call, promise-shaped" },
  { name: "dnsPromises.lookup", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "node",
    description: "node:dns promises lookup()" },
  { name: "socket.gethostbyname", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "python",
    description: "Python socket.gethostbyname() — legacy getaddrinfo wrapper" },
  { name: "socket.getaddrinfo", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "python",
    description: "Python socket.getaddrinfo()" },
  { name: "dns.resolver.resolve", shape: "qualified-function", hostnameArgIdx: 0, ecosystem: "python",
    description: "Python dnspython resolver.resolve()" },
];

/**
 * Project-local wrapper functions — any identifier whose NAME contains
 * one of these tokens is treated as a DNS sink for the heuristic
 * `wrapper-by-name-heuristic` edge case. Matched case-insensitively
 * against the callee text.
 */
export interface DnsWrapperMarker {
  readonly token: string;
  readonly description: string;
}

export const G7_DNS_WRAPPER_MARKERS: readonly DnsWrapperMarker[] = [
  { token: "resolveDns", description: "resolveDns(...) — project-local DNS wrapper" },
  { token: "dnsLookup", description: "dnsLookup(...) — project-local lookup wrapper" },
  { token: "dnsResolve", description: "dnsResolve(...) — project-local resolve wrapper" },
  { token: "resolveHost", description: "resolveHost(...) — project-local resolve wrapper" },
];

// ─── Secret / sensitive-source identifier markers ────────────────────────

/**
 * Sensitive-source markers. G7 elevates confidence when the tainted
 * variable that flows into the hostname has a name matching one of
 * these tokens. Charter lethal edge case 7 (ast-taint-from-secret-source).
 */
export interface SensitiveSourceMarker {
  readonly token: string;
  readonly kind: "credential" | "identity" | "content" | "capability";
  readonly description: string;
}

export const G7_SENSITIVE_SOURCE_MARKERS: readonly SensitiveSourceMarker[] = [
  { token: "TOKEN", kind: "credential", description: "Credential / API token" },
  { token: "SECRET", kind: "credential", description: "Named secret" },
  { token: "KEY", kind: "credential", description: "Key material (API / signing / SSH)" },
  { token: "PASSWORD", kind: "credential", description: "Password field" },
  { token: "CREDENTIAL", kind: "credential", description: "Generic credential bag" },
  { token: "PRIVATE", kind: "credential", description: "Private material (key / pem)" },
  { token: "SESSION", kind: "identity", description: "Session identifier" },
  { token: "COOKIE", kind: "identity", description: "Cookie / browser identity" },
  { token: "AUTH", kind: "credential", description: "Authorization header / auth token" },
  { token: "PII", kind: "content", description: "Personal information tag" },
  { token: "user", kind: "identity", description: "User identifier" },
  { token: "email", kind: "identity", description: "Email address" },
  { token: "data", kind: "content", description: "Generic data payload" },
  { token: "payload", kind: "content", description: "Payload bag" },
];

// ─── Encoding-wrapper markers (entropy heuristic) ────────────────────────

/**
 * Calls whose presence on the path from the secret source to the DNS
 * hostname increases the confidence that the subdomain carries
 * high-entropy encoded data. Charter's subdomain_entropy_score factor
 * inspects this set.
 */
export interface EncodingWrapper {
  readonly name: string;
  readonly shape: "qualified-function" | "bare-function" | "member-call";
  /** Approximate entropy bits-per-char the encoding produces. */
  readonly bitsPerChar: number;
  readonly description: string;
}

export const G7_ENCODING_WRAPPERS: readonly EncodingWrapper[] = [
  { name: "Buffer.from", shape: "qualified-function", bitsPerChar: 5.0,
    description: "Buffer.from(data).toString(...) — base64/hex/ascii encoding hub" },
  { name: "btoa", shape: "bare-function", bitsPerChar: 6.0,
    description: "btoa(data) — base64 encoding" },
  { name: "base64.b64encode", shape: "qualified-function", bitsPerChar: 6.0,
    description: "Python base64.b64encode() — base64 encoding" },
  { name: "crypto.createHash", shape: "qualified-function", bitsPerChar: 4.0,
    description: "crypto.createHash() — hash output, high-entropy subdomain" },
  { name: "encodeURIComponent", shape: "bare-function", bitsPerChar: 5.5,
    description: "encodeURIComponent() — URL-escape, preserves most entropy" },
  { name: "hex", shape: "member-call", bitsPerChar: 4.0,
    description: ".toString(\"hex\") — 4 bits/char nibble encoding" },
];

// ─── Charter-audited hostname allowlist primitives ───────────────────────

/**
 * Calls whose presence in the enclosing function scope indicates a
 * hostname allowlist / validator is checking the hostname before the
 * DNS sink. Severity downgrades to "informational" per charter.
 */
export interface AllowlistMarker {
  readonly name: string;
  readonly shape: "bare-function" | "qualified-function" | "member-call";
  readonly description: string;
}

export const G7_ALLOWLIST_MARKERS: readonly AllowlistMarker[] = [
  { name: "isAllowedHost", shape: "bare-function",
    description: "isAllowedHost() — project-local allowlist helper" },
  { name: "validateHostname", shape: "bare-function",
    description: "validateHostname() — project-local validator" },
  { name: "assertAllowlistedHost", shape: "bare-function",
    description: "assertAllowlistedHost() — throws on non-allowlist host" },
  { name: "ALLOWED_HOSTS.includes", shape: "member-call",
    description: "allowlist membership check" },
];
