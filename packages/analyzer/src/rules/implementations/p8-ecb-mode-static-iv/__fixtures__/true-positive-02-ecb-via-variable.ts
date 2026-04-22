import crypto from "node:crypto";

// Charter lethal edge case #1 — ECB smuggled through a variable binding.
const mode = "aes-128-ecb";

export function encryptWithMode(key: Buffer, iv: Buffer, data: Buffer) {
  const cipher = crypto.createCipheriv(mode, key, iv);
  return cipher.update(data);
}
