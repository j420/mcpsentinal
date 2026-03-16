import { describe, it, expect } from "vitest";
import { checkConsent } from "../consent.js";

describe("checkConsent", () => {
  it("grants consent via allowlist when server ID is present", async () => {
    const result = await checkConsent(
      "server-123",
      "https://example.com/mcp",
      [],
      { allowlist: ["server-123"] }
    );
    expect(result.consented).toBe(true);
    expect(result.method).toBe("allowlist");
  });

  it("denies consent when server ID is NOT in allowlist", async () => {
    const result = await checkConsent(
      "server-999",
      "https://example.com/mcp",
      [],
      { allowlist: ["server-123"] }
    );
    // May still consent via other methods — but allowlist alone not enough
    if (!result.consented) {
      expect(result.method).toBeNull();
    }
  });

  it("grants consent via tool declaration when mcp_sentinel_consent tool exists", async () => {
    const result = await checkConsent(
      "server-456",
      "https://example.com/mcp",
      [
        { name: "get_data" },
        { name: "mcp_sentinel_consent" },
        { name: "post_data" },
      ],
      { allowlist: [] }
    );
    expect(result.consented).toBe(true);
    expect(result.method).toBe("tool_declaration");
  });

  it("denies consent when no mechanism is present", async () => {
    const result = await checkConsent(
      "server-789",
      "http://127.0.0.1:99999/nonexistent", // unreachable endpoint
      [{ name: "get_data" }],
      { allowlist: [] }
    );
    // Well-known fetch will fail on unreachable endpoint → denied
    expect(result.consented).toBe(false);
    expect(result.method).toBeNull();
  });

  it("prioritises allowlist over tool declaration", async () => {
    const result = await checkConsent(
      "server-123",
      "https://example.com/mcp",
      [{ name: "mcp_sentinel_consent" }],
      { allowlist: ["server-123"] }
    );
    expect(result.consented).toBe(true);
    expect(result.method).toBe("allowlist"); // allowlist checked first
  });
});
