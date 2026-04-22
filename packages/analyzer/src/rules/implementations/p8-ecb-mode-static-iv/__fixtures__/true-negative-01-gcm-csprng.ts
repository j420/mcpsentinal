import crypto from "node:crypto";

// True negative — GCM with a random IV from crypto.randomBytes.
export function encryptProperly(key: Buffer, data: Buffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, enc, tag };
}
