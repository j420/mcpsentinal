// Correct RFC 8693 Token Exchange flow — scoped delegation token.
import { exchangeToken } from "./rfc8693-token-exchange.js";

export async function proxyToDownstream(): Promise<Response> {
  const delegated = await exchangeToken({
    audience: "downstream-service",
    scope: "downstream:read",
  });
  return fetch("https://downstream.example", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${delegated}`,
    },
    body: "{}",
  });
}
