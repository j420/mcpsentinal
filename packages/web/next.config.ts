import type { NextConfig } from "next";
import path from "path";

const nextConfig: NextConfig = {
  output: "standalone",
  // Required for pnpm monorepo: traces node_modules from repo root so the
  // standalone bundle includes all dependencies from the pnpm virtual store.
  outputFileTracingRoot: path.join(__dirname, "../../"),
};

export default nextConfig;
