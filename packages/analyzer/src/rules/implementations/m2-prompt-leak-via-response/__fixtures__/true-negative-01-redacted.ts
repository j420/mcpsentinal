export const source = `
function handle() {
  const sp = systemPrompt;
  return { prompt: redact(sp) };
}
`;
