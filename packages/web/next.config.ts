import path from "path";
import crypto from "crypto";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output: @vercel/nft traces and copies actual package files (not pnpm symlinks)
  // into .next/standalone/node_modules — identical deployment model to packages/api (compile → node server.js).
  output: "standalone",
  // Required for pnpm monorepos: tells the file tracer to resolve from the workspace root
  // so it can follow pnpm's .pnpm virtual store symlinks up through /app/node_modules/.
  // __dirname here = /app/packages/web → two levels up = /app (workspace root).
  outputFileTracingRoot: path.join(__dirname, "../../"),
  // Generate a unique build ID per deployment to prevent "Failed to find Server Action" errors.
  // When Railway redeploys, client-side JS references Server Action IDs from the build.
  // Without a unique ID, cached clients may reference stale action hashes.
  generateBuildId: async () => {
    return crypto.randomBytes(8).toString("hex");
  },
};

export default nextConfig;
