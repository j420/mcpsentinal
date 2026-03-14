#!/usr/bin/env bash
# MCP Sentinel — Stop hook: typecheck reminder
#
# Fires when Claude finishes a session.
# Runs pnpm typecheck silently. If it fails, surfaces the errors
# so they're visible before the session closes.
#
# TypeScript type errors are the #1 source of CI failures.
# Catching here is 10x cheaper than catching in CI.

set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo '.')"

# Only run if TypeScript files were modified in this session
if ! git diff --name-only HEAD 2>/dev/null | grep -q "\.ts$" && \
   ! git diff --cached --name-only 2>/dev/null | grep -q "\.ts$"; then
  exit 0
fi

echo ""
echo "Running typecheck on modified TypeScript files..."

if ! pnpm typecheck --silent 2>&1; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  TYPECHECK FAILED — fix before committing                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  pnpm typecheck 2>&1 | tail -30
  echo ""
  exit 1
fi

echo "✓ Typecheck passed"
exit 0
