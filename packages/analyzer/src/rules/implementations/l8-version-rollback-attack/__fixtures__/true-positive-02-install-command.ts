/** L8 TP-02 — install command pins anthropic-sdk to 0.2.3. */
export const source = `
function setupEnv() {
  run("npm install @anthropic/sdk@0.2.3");
  run("pip install modelcontextprotocol==0.1.0");
}
`;
