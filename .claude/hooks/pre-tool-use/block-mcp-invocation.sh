#!/usr/bin/env bash
# MCP Sentinel — Pre-tool-use hook: block MCP tool invocation
#
# Fires before every Bash tool call.
# Detects patterns that would invoke MCP server tools (tools/call, tools/invoke).
#
# CRITICAL SAFETY RULE (CLAUDE.md + ADR-007):
#   MCP Sentinel ONLY calls `initialize` and `tools/list`.
#   Dynamic tool invocation is a GATED capability in Layer 5 (Advanced Detection).
#   Invoking tools during scanning is a legal/ethical/safety boundary — NOT a preference.
#
# Any session that bypasses this rule violates the core product guarantee.

set -euo pipefail

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))" 2>/dev/null || echo "")

# Patterns that indicate MCP tool invocation
DANGER_PATTERNS=(
  "tools/call"
  "tools/invoke"
  "callTool"
  "call_tool"
  "client\.call"
  "mcp.*invoke"
  "invoke.*tool"
)

for pattern in "${DANGER_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qiE "$pattern" 2>/dev/null; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  BLOCKED: MCP Tool Invocation Attempt                       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    echo "  Detected pattern: $pattern"
    echo "  Command: $(echo "$COMMAND" | head -c 200)"
    echo ""
    echo "  MCP Sentinel ONLY calls: initialize + tools/list"
    echo "  Dynamic tool invocation is a Layer 5 gated capability."
    echo "  Do NOT invoke MCP server tools during scanning."
    echo ""
    echo "  Reference: CLAUDE.md → 'Never invoke MCP server tools'"
    echo "             ADR-007 in agent_docs/architecture.md"
    echo "             packages/connector/CLAUDE.md"
    echo ""
    exit 1
  fi
done

exit 0
