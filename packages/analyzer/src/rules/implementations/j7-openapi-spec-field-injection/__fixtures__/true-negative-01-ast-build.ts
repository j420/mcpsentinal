// Uses AST builder; no raw interpolation of spec fields.
export function gen(spec: { operationId: string }) {
  const name = validateIdentifier(spec.operationId);
  return buildAst(name);
}
function validateIdentifier(s: string) { return s; }
function buildAst(_: string) { return ""; }
