#!/usr/bin/env bash
# MCP Sentinel — Validate all detection rules
#
# Checks every YAML file in rules/ has all required fields.
# Exits non-zero if any rule fails validation.
#
# Run before any release:
#   bash tools/scripts/validate-rules.sh
#
# Also run by the release skill step 3.

set -euo pipefail

RULES_DIR="$(git rev-parse --show-toplevel)/rules"
PASS=0
FAIL=0
FAILURES=()

REQUIRED_FIELDS=("id" "name" "category" "severity" "detect" "remediation" "test_cases")
VALID_SEVERITIES=("critical" "high" "medium" "low" "informational")

for yaml_file in "$RULES_DIR"/*.yaml; do
  filename=$(basename "$yaml_file")
  errors=()

  # Check required top-level fields
  for field in "${REQUIRED_FIELDS[@]}"; do
    if ! grep -q "^${field}:" "$yaml_file"; then
      errors+=("missing field: '${field}'")
    fi
  done

  # Check detect.type exists
  if ! grep -qE "^\s+type:" "$yaml_file"; then
    errors+=("missing 'detect.type'")
  fi

  # Check true_positive test cases
  if ! grep -q "true_positive:" "$yaml_file"; then
    errors+=("missing 'test_cases.true_positive'")
  fi

  # Check true_negative test cases
  if ! grep -q "true_negative:" "$yaml_file"; then
    errors+=("missing 'test_cases.true_negative'")
  fi

  # Count test case entries
  TP_COUNT=$(grep -c "expected: true" "$yaml_file" 2>/dev/null || echo 0)
  TN_COUNT=$(grep -c "expected: false" "$yaml_file" 2>/dev/null || echo 0)

  if [[ "$TP_COUNT" -lt 2 ]]; then
    errors+=("insufficient true positives: found ${TP_COUNT}, need ≥2")
  fi
  if [[ "$TN_COUNT" -lt 2 ]]; then
    errors+=("insufficient true negatives: found ${TN_COUNT}, need ≥2")
  fi

  # Validate severity value
  SEVERITY=$(grep "^severity:" "$yaml_file" | awk '{print $2}' | tr -d '"' | tr -d "'")
  if [[ -n "$SEVERITY" ]]; then
    VALID=false
    for vs in "${VALID_SEVERITIES[@]}"; do
      if [[ "$SEVERITY" == "$vs" ]]; then VALID=true; break; fi
    done
    if [[ "$VALID" == "false" ]]; then
      errors+=("invalid severity '${SEVERITY}'")
    fi
  fi

  # Check remediation is not empty
  REMEDIATION=$(grep "^remediation:" "$yaml_file" | sed 's/^remediation: //' | tr -d '"')
  if [[ -z "$REMEDIATION" || "$REMEDIATION" == "TODO" || "$REMEDIATION" == "TBD" ]]; then
    errors+=("remediation is empty or TODO")
  fi

  if [[ ${#errors[@]} -eq 0 ]]; then
    echo "  ✓ $filename"
    PASS=$((PASS + 1))
  else
    echo "  ✗ $filename"
    for err in "${errors[@]}"; do
      echo "      → $err"
    done
    FAIL=$((FAIL + 1))
    FAILURES+=("$filename")
  fi
done

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "Failed rules:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
  echo ""
  echo "Every rule must have: id, name, category, severity, detect (with type),"
  echo "remediation, and test_cases with ≥2 true_positive + ≥2 true_negative."
  echo "See: agent_docs/detection-rules.md"
  exit 1
fi

echo "All rules valid."
exit 0
