import path from "path";
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output: @vercel/nft traces and copies actual package files (not pnpm symlinks)
  // into .next/standalone/node_modules — identical deployment model to packages/api (compile → node server.js).
  output: "standalone",
  // Required for pnpm monorepos: tells the file tracer to resolve from the workspace root
  // so it can follow pnpm's .pnpm virtual store symlinks up through /app/node_modules/.
  // __dirname here = /app/packages/web → two levels up = /app (workspace root).
  outputFileTracingRoot: path.join(__dirname, "../../"),
};

export default nextConfig;
