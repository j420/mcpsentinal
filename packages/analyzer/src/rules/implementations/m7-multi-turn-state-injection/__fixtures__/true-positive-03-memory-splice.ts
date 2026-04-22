export const source = `
function inject(idx, msg) {
  const mem = agent.memory;
  mem.splice(idx, 0, msg);
}
`;
