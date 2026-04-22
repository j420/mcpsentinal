/**
 * B2 — typed catalogue of dangerous parameter names. Each maps to the
 * downstream sink type for evidence narration.
 */

export type DangerousSink =
  | "command-execution"
  | "sql-execution"
  | "code-evaluation"
  | "file-write"
  | "template-render"
  | "network-send";

export const DANGEROUS_PARAM_NAMES: Readonly<Record<string, { sink: DangerousSink; rationale: string }>> = {
  command: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  cmd: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  shell: { sink: "command-execution", rationale: "Name advertises shell command execution" },
  exec: { sink: "command-execution", rationale: "Name advertises exec() call" },
  script: { sink: "command-execution", rationale: "Name advertises script execution" },
  sql: { sink: "sql-execution", rationale: "Name advertises SQL query" },
  query: { sink: "sql-execution", rationale: "Name advertises database query" },
  code: { sink: "code-evaluation", rationale: "Name advertises generic code evaluation" },
  eval: { sink: "code-evaluation", rationale: "Name advertises eval() call" },
  template: { sink: "template-render", rationale: "Name advertises template rendering" },
  path: { sink: "file-write", rationale: "Name advertises filesystem path" },
  file_path: { sink: "file-write", rationale: "Name advertises filesystem path" },
  filepath: { sink: "file-write", rationale: "Name advertises filesystem path" },
  filename: { sink: "file-write", rationale: "Name advertises filesystem path" },
  url: { sink: "network-send", rationale: "Name advertises network endpoint" },
  uri: { sink: "network-send", rationale: "Name advertises network endpoint" },
  endpoint: { sink: "network-send", rationale: "Name advertises network endpoint" },
};
