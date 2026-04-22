export function gen(spec: { summary: string }) {
  const code = `// generated for openapi summary: ${spec.summary}`;
  return code;
}
