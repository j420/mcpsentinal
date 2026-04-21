// True negative: eval with a hardcoded string literal. No taint flows
// to the eval argument — nothing for the analyser to report.
export function trivialEval() {
  return eval("2 + 2");
}
