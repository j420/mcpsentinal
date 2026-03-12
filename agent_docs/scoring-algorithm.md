# MCP Sentinel — Scoring Algorithm

## Algorithm: Score = 100 - Σ(weighted penalties)

### Severity Weights
| Severity | Penalty |
|----------|---------|
| Critical | -25 |
| High | -15 |
| Medium | -8 |
| Low | -3 |
| Informational | -1 |

### Category Sub-Scores
Each category starts at 100 and is reduced independently:
- **Code Score**: Findings from C1-C9 (code-analysis rules)
- **Dependencies Score**: Findings from D1-D4 (dependency-analysis rules)
- **Config Score**: Findings from B1-B4, F1-F4 (schema + ecosystem rules)
- **Description Score**: Findings from A1-A5 (description-analysis rules)
- **Behavior Score**: Findings from E1-E4 (behavioral-analysis rules)

### Special Rules
1. **Lethal Trifecta (F1)**: If detected, total score is CAPPED at 40 regardless of other findings.
2. **Floor**: Score never goes below 0.
3. **Ceiling**: Score never goes above 100.

### OWASP Coverage
The OWASP posture is a boolean map: for each of the 10 OWASP MCP categories, `true` = no findings in that category (clean), `false` = has findings.

### Score Interpretation
| Range | Rating | Badge Color |
|-------|--------|-------------|
| 80-100 | Good | Green |
| 60-79 | Moderate | Yellow |
| 40-59 | Poor | Orange |
| 0-39 | Critical | Red |
