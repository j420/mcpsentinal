// True positive: AWS permanent access key ID. Exactly 16 uppercase
// alphanumeric characters after the `AKIA` prefix. Committed as a
// module-level constant used by an S3 client.
import { S3Client } from "@aws-sdk/client-s3";

export const s3 = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: "AKIA1234567890ABCDEF",
    secretAccessKey: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234",
  },
});
