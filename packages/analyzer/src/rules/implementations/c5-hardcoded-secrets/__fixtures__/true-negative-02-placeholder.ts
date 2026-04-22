// True negative: placeholder marker on the same line suppresses the finding.
// The shape matches `sk-ant-` but the body contains REPLACE-ME — the
// CHARTER explicitly suppresses such findings because example files use
// this pattern intentionally.
export const config = {
  // Example: Anthropic API key. Replace in production.
  api_key: "sk-ant-api03-REPLACE-ME-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
};
