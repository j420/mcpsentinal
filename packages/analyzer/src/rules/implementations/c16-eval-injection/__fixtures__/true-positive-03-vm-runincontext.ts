// True positive: vm.runInNewContext on user code — NOT a safe sandbox.
// The sandbox argument is a plain object, not a security boundary.
import vm from "node:vm";

export function run(req: { body: { code: string } }) {
  const code = req.body.code;
  return vm.runInNewContext(code, { console });
}
