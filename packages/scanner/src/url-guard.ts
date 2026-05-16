/**
 * P21 — Public Scan Surface Engineer
 * url-guard.ts — SSRF defence for the ad-hoc scan surface.
 *
 * The ad-hoc scanner connects to URLs supplied by anonymous, untrusted
 * visitors. Without this guard, a submitter could make MCP Sentinel connect
 * to internal infrastructure: localhost services, RFC1918 hosts, or the
 * cloud metadata endpoint (169.254.169.254). That is server-side request
 * forgery.
 *
 * SAFETY OATH (P21, binding): no public code path connects to a URL until
 * it has passed `assertSafe()`. `assertSafe()` resolves the hostname and
 * validates EVERY resolved IP, so a hostname that resolves to an internal
 * address is rejected before any socket opens.
 *
 * Residual risk (documented, not hidden): a DNS-rebinding attacker can
 * change the A record between our `lookup()` and the MCP SDK transport's
 * own connect. `assertSafe()` closes the obvious window (literal IPs,
 * stable DNS); full pinning would require a custom HTTP agent threaded
 * through the SDK transport — tracked as a follow-up.
 */

import { lookup } from "node:dns/promises";
import net from "node:net";

/** Thrown when a URL fails validation. `reason` is a stable machine code. */
export class UrlGuardError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
  ) {
    super(message);
    this.name = "UrlGuardError";
  }
}

// ─── IPv4 range classification ───────────────────────────────────────────────

/** Parse a dotted-decimal IPv4 string to an unsigned 32-bit integer, or null. */
function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

interface V4Range {
  base: number;
  bits: number;
  reason: string;
}

function v4Range(cidr: string, reason: string): V4Range {
  const [ip, bitsStr] = cidr.split("/");
  const base = ipv4ToInt(ip);
  if (base === null) throw new Error(`bad CIDR in url-guard: ${cidr}`);
  return { base, bits: Number(bitsStr), reason };
}

/**
 * Address ranges that must never be reachable from a public scan.
 * Covers loopback, every RFC1918 private block, the link-local range
 * (which contains the cloud metadata endpoint 169.254.169.254),
 * carrier-grade NAT, and reserved/multicast space.
 */
const BLOCKED_V4: V4Range[] = [
  v4Range("0.0.0.0/8", "unspecified"),
  v4Range("10.0.0.0/8", "private-rfc1918"),
  v4Range("100.64.0.0/10", "carrier-grade-nat"),
  v4Range("127.0.0.0/8", "loopback"),
  v4Range("169.254.0.0/16", "link-local"),
  v4Range("172.16.0.0/12", "private-rfc1918"),
  v4Range("192.0.0.0/24", "ietf-protocol-assignment"),
  v4Range("192.168.0.0/16", "private-rfc1918"),
  v4Range("198.18.0.0/15", "benchmarking"),
  v4Range("224.0.0.0/4", "multicast"),
  v4Range("240.0.0.0/4", "reserved"),
];

function classifyV4(ip: string): string | null {
  const n = ipv4ToInt(ip);
  if (n === null) return null;
  for (const range of BLOCKED_V4) {
    const mask = range.bits === 0 ? 0 : (0xffffffff << (32 - range.bits)) >>> 0;
    if ((n & mask) === (range.base & mask)) return range.reason;
  }
  return null;
}

// ─── IPv6 range classification ───────────────────────────────────────────────

/** Return the first 16-bit hextet of an IPv6 address as an integer. */
function firstHextet(ip: string): number {
  if (ip.startsWith("::")) return 0;
  const first = ip.split(":")[0];
  if (!first) return 0;
  const value = parseInt(first, 16);
  return Number.isNaN(value) ? 0 : value;
}

function classifyV6(ip: string): string | null {
  const lower = ip.toLowerCase();

  if (lower === "::1") return "loopback";
  if (lower === "::" || lower === "::0") return "unspecified";

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible — re-check the v4 part.
  const mappedDotted = lower.match(/:((?:\d{1,3}\.){3}\d{1,3})$/);
  if (mappedDotted) {
    const v4 = classifyV4(mappedDotted[1]);
    if (v4) return v4;
  }

  const head = firstHextet(lower);
  // Unique-local addresses fc00::/7 — first byte is 0xfc or 0xfd.
  if ((head >> 8) === 0xfc || (head >> 8) === 0xfd) return "ipv6-unique-local";
  // Link-local fe80::/10 — first 10 bits are 1111111010.
  if (head >= 0xfe80 && head <= 0xfebf) return "ipv6-link-local";

  return null;
}

/**
 * Classify an IP literal. Returns a stable machine reason string when the
 * address is in a blocked range, or null when the address is safe to reach.
 */
export function classifyAddress(ip: string): string | null {
  const family = net.isIP(ip);
  if (family === 4) return classifyV4(ip);
  if (family === 6) return classifyV6(ip);
  return null;
}

// ─── URL validation ──────────────────────────────────────────────────────────

/**
 * Synchronous parse + scheme validation. No DNS. Throws `UrlGuardError`
 * on a malformed URL or a non-http(s) scheme.
 *
 * Note: the WHATWG URL parser normalises obfuscated IPv4 forms — integer
 * (`http://2130706433`), hex (`http://0x7f000001`), and octal — into
 * dotted-decimal on `url.hostname`, so those bypasses are closed here.
 */
export function parseAndValidate(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new UrlGuardError(`Invalid URL: ${rawUrl}`, "invalid-url");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UrlGuardError(
      `Unsupported URL scheme: ${url.protocol} (only http and https are allowed)`,
      "bad-scheme",
    );
  }
  return url;
}

/**
 * Full SSRF check. Parses + validates the scheme, then — if the host is a
 * DNS name — resolves it and rejects if ANY resolved address is in a
 * blocked range. If the host is already an IP literal it is checked
 * directly. Returns the validated `URL` on success.
 *
 * This MUST be called before MCPConnector.enumerate() on any URL that
 * originated from an anonymous request.
 */
export async function assertSafe(rawUrl: string): Promise<URL> {
  const url = parseAndValidate(rawUrl);

  // url.hostname keeps IPv6 literals wrapped in brackets — strip them.
  const host = url.hostname.replace(/^\[/, "").replace(/\]$/, "");

  if (host === "") {
    throw new UrlGuardError("URL has no host", "no-host");
  }

  // Host is already an IP literal — classify directly, no DNS.
  if (net.isIP(host) !== 0) {
    const reason = classifyAddress(host);
    if (reason) {
      throw new UrlGuardError(
        `Blocked address (${reason}): ${host}`,
        reason,
      );
    }
    return url;
  }

  // Host is a DNS name — resolve every address and validate each.
  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookup(host, { all: true });
  } catch {
    throw new UrlGuardError(
      `DNS resolution failed for host: ${host}`,
      "dns-failure",
    );
  }

  if (addresses.length === 0) {
    throw new UrlGuardError(`Host resolved to no addresses: ${host}`, "dns-empty");
  }

  for (const { address } of addresses) {
    const reason = classifyAddress(address);
    if (reason) {
      throw new UrlGuardError(
        `Host ${host} resolves to a blocked address ${address} (${reason})`,
        reason,
      );
    }
  }

  return url;
}
