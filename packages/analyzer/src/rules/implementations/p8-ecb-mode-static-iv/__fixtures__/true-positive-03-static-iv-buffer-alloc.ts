import crypto from "node:crypto";

// Charter lethal edge case #2 — Buffer.alloc(16) is a zero IV.
const iv = Buffer.alloc(16);

export function encryptWithZeroIv(key: Buffer, data: Buffer) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return cipher.update(data);
}
