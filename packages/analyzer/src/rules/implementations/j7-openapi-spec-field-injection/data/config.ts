export const J7_CONFIDENCE_CAP = 0.88;

/**
 * Interpolation-marker tokens that, combined with an OpenAPI spec
 * field reference on the same line, signal potential injection.
 * Individual typed records, per the no-static-patterns guard.
 */
export interface InterpolationTokenSpec {
  readonly token: string;
  readonly kind: "template-literal" | "concat" | "fs-write";
}

export const J7_INTERPOLATION_MARKERS: Readonly<
  Record<string, InterpolationTokenSpec>
> = {
  template_open: { token: "${", kind: "template-literal" },
  string_concat_plus: { token: "+", kind: "concat" },
  fs_write_file: { token: "writeFile", kind: "fs-write" },
  fs_write_file_sync: { token: "writeFileSync", kind: "fs-write" },
};
