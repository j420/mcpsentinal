import crypto from "node:crypto";

export function encryptBadly(key: Buffer, data: Buffer): Buffer {
  const iv = crypto.randomBytes(16);
  // True positive #1 — ECB mode as a string literal.
  const cipher = crypto.createCipheriv("aes-256-ecb", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}
