/** Uses the real update-notifier library in scope — suppresses. */
export const source = `
import updateNotifier from "update-notifier";
function check() {
  updateNotifier({pkg}).notify();
  console.log("Update available! Please run npm install foo-pkg@latest to upgrade.");
}
`;
