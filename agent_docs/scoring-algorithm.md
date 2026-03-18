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
- **Code Score**: Findings from C1-C16 (code-analysis rules)
- **Dependencies Score**: Findings from D1-D7 (dependency-analysis rules)
- **Config Score**: Findings from B1-B7, F1-F7, G1-G7, H1-H3, I1-I16, J1-J7, K1-K20, L1-L15, M1-M9, N1-N15, O1-O10, P1-P10, Q1-Q15 (schema + ecosystem + adversarial-ai + 2026 attack surface + protocol-surface + threat-intelligence + compliance-governance + supply-chain-advanced + ai-runtime-exploitation + protocol-edge-cases + data-privacy-attacks + infrastructure-runtime + cross-ecosystem-emergent rules)
- **Description Score**: Findings from A1-A9 (description-analysis rules)
- **Behavior Score**: Findings from E1-E4 (behavioral-analysis rules)

### Category Mapping
The scorer maps rule categories to sub-scores via `CATEGORY_MAP`:
| Rule Category | Sub-Score |
|---|---|
| `code-analysis` | `code_score` |
| `dependency-analysis` | `deps_score` |
| `behavioral-analysis` | `behavior_score` |
| `description-analysis` | `description_score` |
| `schema-analysis` | `config_score` |
| `ecosystem-context` | `config_score` |
| `adversarial-ai` | `config_score` |
| `auth-analysis` | `config_score` |
| `protocol-surface` | `config_score` |
| `threat-intelligence` | `config_score` |
| `compliance-governance` | `config_score` |
| `supply-chain-advanced` | `config_score` |
| `ai-runtime-exploitation` | `config_score` |
| `protocol-edge-cases` | `config_score` |
| `data-privacy-attacks` | `config_score` |
| `infrastructure-runtime` | `config_score` |
| `cross-ecosystem-emergent` | `config_score` |

### Special Rules
1. **Lethal Trifecta (F1)**: If detected, total score is CAPPED at 40 regardless of other findings.
2. **Cross-Config Lethal Trifecta (I13)**: Same cap at 40, but detects the trifecta distributed across multiple servers in the same client configuration.
3. **Floor**: Score never goes below 0.
4. **Ceiling**: Score never goes above 100.

### OWASP Coverage
The OWASP posture is a boolean map: for each of the 10 OWASP MCP categories, `true` = no findings in that category (clean), `false` = has findings.

### Score Interpretation
| Range | Rating | Badge Color |
|-------|--------|-------------|
| 80-100 | Good | Green |
| 60-79 | Moderate | Yellow |
| 40-59 | Poor | Orange |
| 0-39 | Critical | Red |
