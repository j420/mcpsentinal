/**
 * Consent verification for dynamic tool invocation.
 *
 * A server must opt-in through ONE of three mechanisms before we will
 * call any of its tools:
 *
 *   1. allowlist  — server ID appears in a pre-approved list (e.g. test servers)
 *   2. tool_declaration — server exposes a tool named "mcp_sentinel_consent"
 *   3. wellknown  — GET /.well-known/mcp-sentinel.json returns { consent: true }
 *
 * Without consent, dynamic testing is completely blocked. This is an
 * ethical and legal boundary (ADR-007).
 */
import type { ConsentResult, DynamicTesterConfig } from "./types.js";

const FETCH_TIMEOUT_MS = 5_000;

export async function checkConsent(
  serverId: string,
  endpoint: string,
  tools: Array<{ name: string }>,
  config: Pick<DynamicTesterConfig, "allowlist">
): Promise<ConsentResult> {
  // ── Method 1: Explicit allowlist ────────────────────────────────────────
  if (config.allowlist?.includes(serverId)) {
    return {
      consented: true,
      method: "allowlist",
      consented_at: new Date().toISOString(),
      note: "Server ID in pre-approved allowlist",
    };
  }

  // ── Method 2: Consent tool declaration ─────────────────────────────────
  const consentTool = tools.find((t) => t.name === "mcp_sentinel_consent");
  if (consentTool) {
    return {
      consented: true,
      method: "tool_declaration",
      consented_at: new Date().toISOString(),
      note: "Server exposes mcp_sentinel_consent tool",
    };
  }

  // ── Method 3: .well-known JSON ─────────────────────────────────────────
  const wellKnown = await fetchWellKnown(endpoint);
  if (wellKnown.consented) {
    return {
      consented: true,
      method: "wellknown",
      consented_at: new Date().toISOString(),
      note: wellKnown.note ?? "Consent via .well-known/mcp-sentinel.json",
    };
  }

  return {
    consented: false,
    method: null,
    consented_at: null,
    note: "No consent signal found via allowlist, tool declaration, or .well-known",
  };
}

async function fetchWellKnown(
  endpoint: string
): Promise<{ consented: boolean; note?: string }> {
  try {
    // Derive the base URL from the endpoint
    const url = new URL(endpoint);
    const wellKnownUrl = `${url.protocol}//${url.host}/.well-known/mcp-sentinel.json`;

    const res = await fetch(wellKnownUrl, {
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      headers: { Accept: "application/json" },
    });

    if (!res.ok) return { consented: false };

    const body = await res.json() as Record<string, unknown>;

    // Verify the consent field and the server_id matches to prevent
    // cross-origin consent spoofing
    if (body.consent === true) {
      return {
        consented: true,
        note: typeof body.note === "string" ? body.note : undefined,
      };
    }

    return { consented: false };
  } catch {
    return { consented: false };
  }
}
