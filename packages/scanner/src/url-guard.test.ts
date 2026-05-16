/**
 * url-guard tests — SSRF defence for the ad-hoc scan surface.
 *
 * Every blocked address class must be rejected. DNS-name resolution is
 * exercised by stubbing node:dns/promises so the suite is hermetic.
 */

import { describe, it, expect, vi, afterEach } from "vitest";
import { parseAndValidate, classifyAddress, assertSafe, UrlGuardError } from "./url-guard.js";

vi.mock("node:dns/promises", () => ({
  lookup: vi.fn(),
}));

import { lookup } from "node:dns/promises";
const mockedLookup = vi.mocked(lookup);

afterEach(() => {
  vi.clearAllMocks();
});

describe("parseAndValidate", () => {
  it("accepts http and https URLs", () => {
    expect(parseAndValidate("http://example.com/mcp").protocol).toBe("http:");
    expect(parseAndValidate("https://example.com/mcp").protocol).toBe("https:");
  });

  it("rejects non-http(s) schemes", () => {
    for (const url of ["file:///etc/passwd", "ftp://example.com", "gopher://x"]) {
      expect(() => parseAndValidate(url)).toThrow(UrlGuardError);
    }
  });

  it("rejects malformed URLs", () => {
    expect(() => parseAndValidate("not a url")).toThrow(UrlGuardError);
  });

  it("normalises obfuscated integer/hex IPv4 to dotted-decimal", () => {
    // WHATWG URL parser collapses these into 127.0.0.1
    expect(parseAndValidate("http://2130706433/").hostname).toBe("127.0.0.1");
    expect(parseAndValidate("http://0x7f000001/").hostname).toBe("127.0.0.1");
  });
});

describe("classifyAddress", () => {
  it("blocks loopback", () => {
    expect(classifyAddress("127.0.0.1")).toBe("loopback");
    expect(classifyAddress("127.42.9.1")).toBe("loopback");
    expect(classifyAddress("::1")).toBe("loopback");
  });

  it("blocks RFC1918 private ranges", () => {
    expect(classifyAddress("10.0.0.5")).toBe("private-rfc1918");
    expect(classifyAddress("172.16.0.1")).toBe("private-rfc1918");
    expect(classifyAddress("172.31.255.255")).toBe("private-rfc1918");
    expect(classifyAddress("192.168.1.1")).toBe("private-rfc1918");
  });

  it("blocks the cloud metadata endpoint and link-local range", () => {
    expect(classifyAddress("169.254.169.254")).toBe("link-local");
    expect(classifyAddress("169.254.0.1")).toBe("link-local");
  });

  it("blocks unspecified, carrier-grade NAT, multicast and reserved", () => {
    expect(classifyAddress("0.0.0.0")).toBe("unspecified");
    expect(classifyAddress("100.64.0.1")).toBe("carrier-grade-nat");
    expect(classifyAddress("224.0.0.1")).toBe("multicast");
    expect(classifyAddress("240.0.0.1")).toBe("reserved");
  });

  it("blocks IPv6 ULA and link-local", () => {
    expect(classifyAddress("fc00::1")).toBe("ipv6-unique-local");
    expect(classifyAddress("fd12:3456::1")).toBe("ipv6-unique-local");
    expect(classifyAddress("fe80::1")).toBe("ipv6-link-local");
  });

  it("blocks IPv4-mapped IPv6 pointing at internal space", () => {
    expect(classifyAddress("::ffff:127.0.0.1")).toBe("loopback");
    expect(classifyAddress("::ffff:169.254.169.254")).toBe("link-local");
  });

  it("allows public addresses", () => {
    expect(classifyAddress("8.8.8.8")).toBeNull();
    expect(classifyAddress("1.1.1.1")).toBeNull();
    expect(classifyAddress("2606:4700:4700::1111")).toBeNull();
  });
});

describe("assertSafe", () => {
  it("rejects a literal loopback URL before any DNS lookup", async () => {
    await expect(assertSafe("http://127.0.0.1:3100/mcp")).rejects.toThrow(UrlGuardError);
    expect(mockedLookup).not.toHaveBeenCalled();
  });

  it("rejects the literal cloud metadata endpoint", async () => {
    await expect(
      assertSafe("http://169.254.169.254/latest/meta-data/"),
    ).rejects.toMatchObject({ reason: "link-local" });
    expect(mockedLookup).not.toHaveBeenCalled();
  });

  it("rejects a bracketed IPv6 loopback literal", async () => {
    await expect(assertSafe("http://[::1]:8080/mcp")).rejects.toThrow(UrlGuardError);
  });

  it("rejects a hostname that resolves to a private address", async () => {
    mockedLookup.mockResolvedValue([{ address: "10.0.0.7", family: 4 }] as never);
    await expect(assertSafe("https://internal.example.com/mcp")).rejects.toMatchObject({
      reason: "private-rfc1918",
    });
  });

  it("rejects when ANY resolved address is internal (DNS-rebinding shape)", async () => {
    mockedLookup.mockResolvedValue([
      { address: "8.8.8.8", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ] as never);
    await expect(assertSafe("https://rebind.example.com/mcp")).rejects.toMatchObject({
      reason: "loopback",
    });
  });

  it("rejects when DNS resolution fails", async () => {
    mockedLookup.mockRejectedValue(new Error("ENOTFOUND"));
    await expect(assertSafe("https://nonexistent.example.com/mcp")).rejects.toMatchObject({
      reason: "dns-failure",
    });
  });

  it("accepts a hostname that resolves only to public addresses", async () => {
    mockedLookup.mockResolvedValue([{ address: "93.184.216.34", family: 4 }] as never);
    const url = await assertSafe("https://example.com/mcp");
    expect(url.hostname).toBe("example.com");
  });
});
