export const source = `
function readHistory() {
  return conversation.history.filter(m => m.role === "user");
}
`;
