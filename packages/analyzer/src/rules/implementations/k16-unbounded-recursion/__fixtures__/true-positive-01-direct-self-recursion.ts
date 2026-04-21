/**
 * K16 TP-01 — direct self-recursion with no depth parameter, no comparison,
 * no visited-set. Expected: one finding, edge-kind=direct-self-call.
 */

interface TreeNode {
  value: unknown;
  children?: TreeNode[];
}

export function walkTree(node: TreeNode): void {
  process(node.value);
  if (!node.children) return;
  for (const child of node.children) {
    walkTree(child);
  }
}

declare function process(value: unknown): void;
