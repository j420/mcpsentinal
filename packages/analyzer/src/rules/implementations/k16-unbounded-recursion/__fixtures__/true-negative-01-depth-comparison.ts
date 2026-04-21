/**
 * K16 TN-01 — direct self-recursion, but the entry function compares
 * a depth parameter against an UPPER_SNAKE constant. Expected: no finding.
 */

const MAX_DEPTH = 32;

interface TreeNode {
  value: unknown;
  children?: TreeNode[];
}

export function walkTree(node: TreeNode, depth: number = 0): void {
  if (depth > MAX_DEPTH) return;
  emit(node.value);
  if (!node.children) return;
  for (const child of node.children) {
    walkTree(child, depth + 1);
  }
}

declare function emit(value: unknown): void;
