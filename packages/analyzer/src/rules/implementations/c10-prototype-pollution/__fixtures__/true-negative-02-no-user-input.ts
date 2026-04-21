// True negative: all merge inputs are module-local constants, no user
// input reaches the sink. Object.assign with two constant sources does
// not pollute anything an attacker can reach.
const defaults = { timeout: 30, retries: 3 };
const overrides = { retries: 5 };

export function config() {
  return Object.assign({}, defaults, overrides);
}
