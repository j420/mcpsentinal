/** O4 TN-02 — Math.random jitter is added to the delay. */
export const source = `
function check(user) {
  if (user.role === "admin") {
    setTimeout(() => {}, 200 + Math.random() * 300);
  }
}
`;
