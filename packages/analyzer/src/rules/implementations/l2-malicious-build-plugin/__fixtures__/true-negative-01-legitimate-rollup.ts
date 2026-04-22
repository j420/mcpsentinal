// rollup.config.ts — legitimate configuration, all plugin hooks are pure
import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import { defineConfig } from "rollup";

export default defineConfig({
  input: "src/index.ts",
  output: { dir: "dist", format: "esm" },
  plugins: [
    commonjs(),
    resolve(),
    {
      name: "build-info",
      generateBundle: (_options, bundle) => {
        // pure transformation — list chunk sizes, no network, no exec
        for (const name of Object.keys(bundle)) {
          console.log(`chunk ${name}`);
        }
      },
    },
  ],
});
