// True negative: no JWT calls at all. The rule must be silent — not
// every source file touches JWT.
export function greet(name: string) {
  return `hello ${name}`;
}

export const pi = 3.14159;
