/**
 * B1 — typed records of the JSON Schema validation keywords we look for.
 */

export const STRING_CONSTRAINTS: Readonly<Record<string, true>> = {
  maxLength: true,
  minLength: true,
  enum: true,
  pattern: true,
  format: true,
  const: true,
};

export const NUMBER_CONSTRAINTS: Readonly<Record<string, true>> = {
  minimum: true,
  maximum: true,
  exclusiveMinimum: true,
  exclusiveMaximum: true,
  multipleOf: true,
  enum: true,
  const: true,
};
