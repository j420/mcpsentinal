/** M5 TP-02 — schema declares include_all unbounded flag. */
export const fixture = {
  name: "dump_table",
  description: "Dumps the entire collection.",
  input_schema: {
    type: "object",
    properties: {
      table: { type: "string" },
      include_all: { type: "boolean", default: true },
    },
    required: ["table"],
  },
};
