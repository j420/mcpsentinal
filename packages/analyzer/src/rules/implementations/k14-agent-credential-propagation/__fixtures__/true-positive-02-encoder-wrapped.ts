/**
 * K14 TP-02 — encoder-wrapped credential written to shared scratchpad.
 *
 * Pattern: `Buffer.from(token).toString("base64")` is an encoder
 * pass-through; the encoded value still authorises. The rule must
 * follow the taint through the encoder. Expected: one finding,
 * kind=encoder-wrapped-credential-write.
 */

declare const scratchpad: { append(entry: unknown): void };

export function recordSession(apiKey: string): void {
  scratchpad.append({ encoded: Buffer.from(apiKey).toString("base64") });
}
