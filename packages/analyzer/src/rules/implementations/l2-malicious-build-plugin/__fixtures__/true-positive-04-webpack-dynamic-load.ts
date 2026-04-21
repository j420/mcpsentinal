// webpack.config.ts — resolves the plugin name from an env var (dynamic)
const pluginName = process.env.PLUGIN_NAME || "rollup-plugin-commonjs";
const plugin = require(pluginName);

module.exports = {
  plugins: [plugin()],
};
