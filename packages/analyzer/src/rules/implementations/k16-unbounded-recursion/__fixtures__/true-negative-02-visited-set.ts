/**
 * K16 TN-02 — recursion with a visited-set cycle breaker. Entry
 * function instantiates a Set AND consults it via `.has` / `.add`
 * before recursing. Expected: no finding.
 */

interface GraphNode {
  id: string;
  neighbors: GraphNode[];
}

export function walkGraph(node: GraphNode, visited: Set<string> = new Set<string>()): void {
  if (visited.has(node.id)) return;
  visited.add(node.id);
  emit(node.id);
  for (const n of node.neighbors) {
    walkGraph(n, visited);
  }
}

declare function emit(id: string): void;
