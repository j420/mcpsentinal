#!/usr/bin/env bash
# MCP Sentinel — Post-edit hook: validate detection rule YAML files
#
# Fires after every Edit or Write tool call.
# If the edited file is in rules/*.yaml, validates required fields are present.
# Exits non-zero with a clear message if validation fails.
#
# Required fields per detection-rules.md:
#   id, name, category, severity, detect, remediation, test_cases (with TP + TN)

set -euo pipefail

# Read the tool input JSON from stdin to get the file path
INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('file_path','') or d.get('path',''))" 2>/dev/null || echo "")

# Only run on files in the rules/ directory
if [[ ! "$FILE_PATH" =~ rules/.*\.yaml$ ]]; then
  exit 0
fi

# File must exist
if [[ ! -f "$FILE_PATH" ]]; then
  exit 0
fi

ERRORS=()

# Check required top-level fields
for field in id name category severity detect remediation test_cases; do
  if ! grep -q "^${field}:" "$FILE_PATH"; then
    ERRORS+=("Missing required field: '${field}'")
  fi
done

# Check detect.type exists
if ! grep -qE "^\s+type:" "$FILE_PATH"; then
  ERRORS+=("Missing 'detect.type' — must be one of: regex, schema-check, behavioral, composite")
fi

# Check test_cases has true_positive entries
if ! grep -q "true_positive:" "$FILE_PATH"; then
  ERRORS+=("Missing 'test_cases.true_positive' — minimum 2 true positive test cases required")
fi

# Check test_cases has true_negative entries
if ! grep -q "true_negative:" "$FILE_PATH"; then
  ERRORS+=("Missing 'test_cases.true_negative' — minimum 2 true negative test cases required")
fi

# Count true_positive entries (each starts with "- {")
TP_COUNT=$(grep -c "^\s*-\s*{" "$FILE_PATH" 2>/dev/null | head -1 || echo 0)
if [[ "$TP_COUNT" -lt 2 ]]; then
  ERRORS+=("Insufficient test cases — minimum 2 TP + 2 TN required (found: ${TP_COUNT} total entries)")
fi

# Check severity is a valid value
SEVERITY=$(grep "^severity:" "$FILE_PATH" | awk '{print $2}' | tr -d '"')
VALID_SEVERITIES=("critical" "high" "medium" "low" "informational")
if [[ -n "$SEVERITY" ]]; then
  VALID=false
  for vs in "${VALID_SEVERITIES[@]}"; do
    if [[ "$SEVERITY" == "$vs" ]]; then VALID=true; break; fi
  done
  if [[ "$VALID" == "false" ]]; then
    ERRORS+=("Invalid severity '${SEVERITY}' — must be one of: critical, high, medium, low, informational")
  fi
fi

if [[ ${#ERRORS[@]} -gt 0 ]]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  RULE VALIDATION FAILED: $(basename "$FILE_PATH")           "
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  for err in "${ERRORS[@]}"; do
    echo "  ✗ $err"
  done
  echo ""
  echo "  Every rule MUST have: id, name, category, severity, detect,"
  echo "  remediation, and test_cases with ≥2 true_positive + ≥2 true_negative."
  echo "  See: agent_docs/detection-rules.md"
  echo ""
  exit 1
fi

echo "✓ Rule validation passed: $(basename "$FILE_PATH")"
exit 0
