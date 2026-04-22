export function gen(spec: { operationId: string }) {
  const src = "const openapi " + spec.operationId + " = fn";
  return src;
}
