/**
 * K18 TP-02 — vault.getCredential() result returned from a handler.
 * Expected: one finding, sensitive_source_credential_call.
 */

declare const vault: { getCredential(name: string): string };

export function handler(): { credential: string } {
  const credential = vault.getCredential("db");
  return { credential };
}
