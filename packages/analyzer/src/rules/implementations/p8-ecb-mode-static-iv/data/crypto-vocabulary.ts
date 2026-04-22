/**
 * P8 — canonical crypto-vocabulary registry.
 *
 * Typed Records. No string-literal arrays > 5. Each family is looked up
 * by the gatherer when inspecting AST nodes.
 */

/** IV / nonce / salt identifier tokens (lowercase). Case-insensitive by
 * the gatherer — a binding "IV", "iv", "_iv", "nonce_", "salt" all match. */
export const IV_IDENTIFIER_TOKENS: Record<string, true> = {
  iv: true,
  nonce: true,
  salt: true,
};

/** Cipher-family keywords that together with "ECB" indicate crypto context. */
export const CIPHER_FAMILY_TOKENS: Record<string, true> = {
  aes: true,
  des: true,
  cipher: true,
  encrypt: true,
  decrypt: true,
};

/** Crypto-context tokens whose presence in the enclosing function body
 * promotes a Math.random() call into a crypto misuse. */
export const CRYPTO_CONTEXT_TOKENS: Record<string, true> = {
  key: true,
  secret: true,
  iv: true,
  nonce: true,
  salt: true,
  token: true,
  encrypt: true,
  decrypt: true,
  cipher: true,
  hmac: true,
  sign: true,
  verify: true,
  kdf: true,
};

/** CSPRNG fingerprints. Presence of ANY of these in the file counts as
 * a nearby-CSPRNG mitigation signal. */
export const CSPRNG_FINGERPRINTS: Record<string, true> = {
  "crypto.randombytes": true,
  "crypto.getrandomvalues": true,
  "crypto.randomuuid": true,
  "crypto.randomfillsync": true,
  "crypto.randomfill": true,
  "crypto.webcrypto": true,
  "randombytes(": true,
};

/** Variant ids. */
export type P8VariantId = "ecb_mode" | "static_iv" | "math_random_crypto";
