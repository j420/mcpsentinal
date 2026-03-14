#!/usr/bin/env bash
# MCP Sentinel — Post-edit hook: enforce no inline SQL outside packages/database
#
# Fires after every Edit or Write tool call.
# Detects raw SQL patterns in TypeScript files outside packages/database/.
# CLAUDE.md rule: "Database queries go in packages/database/queries/ — never inline SQL."

set -euo pipefail

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('file_path','') or d.get('path',''))" 2>/dev/null || echo "")

# Only check TypeScript files
if [[ ! "$FILE_PATH" =~ \.ts$ ]]; then
  exit 0
fi

# Allow files inside packages/database/
if [[ "$FILE_PATH" =~ packages/database/ ]]; then
  exit 0
fi

# Allow test fixtures and seeds
if [[ "$FILE_PATH" =~ (fixtures|seed|test) ]]; then
  exit 0
fi

# File must exist
if [[ ! -f "$FILE_PATH" ]]; then
  exit 0
fi

# Detect inline SQL patterns
SQL_PATTERNS=(
  "SELECT .* FROM"
  "INSERT INTO"
  "UPDATE .* SET"
  "DELETE FROM"
  "CREATE TABLE"
  "DROP TABLE"
  "ALTER TABLE"
  "WHERE .* ="
)

MATCHES=()
for pattern in "${SQL_PATTERNS[@]}"; do
  if grep -qiE "$pattern" "$FILE_PATH" 2>/dev/null; then
    LINE=$(grep -inE "$pattern" "$FILE_PATH" | head -1)
    MATCHES+=("$LINE")
  fi
done

if [[ ${#MATCHES[@]} -gt 0 ]]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  INLINE SQL DETECTED outside packages/database/             ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  File: $FILE_PATH"
  echo ""
  for match in "${MATCHES[@]}"; do
    echo "  → $match"
  done
  echo ""
  echo "  All SQL queries must live in: packages/database/queries/"
  echo "  Other packages import from @mcp-sentinel/database."
  echo "  See: packages/database/CLAUDE.md"
  echo ""
  exit 1
fi

exit 0
