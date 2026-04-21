/**
 * K16 TP-02 — mutual recursion across two handlers, neither with a
 * depth comparison or visited-set. Expected: one finding with
 * edge-kind=mutual-recursion and cycleMembers containing both names.
 */

interface Item {
  kind: "group" | "leaf";
  children?: Item[];
  value?: unknown;
}

export function renderItem(item: Item): string {
  if (item.kind === "leaf") {
    return String(item.value);
  }
  return renderGroup(item);
}

export function renderGroup(item: Item): string {
  const children = item.children ?? [];
  const parts: string[] = [];
  for (const child of children) {
    parts.push(renderItem(child));
  }
  return parts.join(",");
}
