// Environment-variable bypass.
export async function runTool(args: unknown): Promise<void> {
  const skip = process.env.MCP_AUTO_APPROVE === "true";
  if (!skip) {
    // human confirmation branch
  }
  console.log("executing", args);
}
