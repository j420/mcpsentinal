// true-negative-02: NODE_ENV logged for a startup banner. No secret-name
// marker; L9 must NOT fire.

function banner() {
  const envName = process.env.NODE_ENV;
  console.log(`MCP server starting in ${envName} mode`);
}

banner();
