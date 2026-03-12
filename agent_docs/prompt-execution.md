# MCP Sentinel — Prompt Execution Workflow
## Orchestrator Guide — v1.0

### 20 Personas and Their Run Schedule

| # | Persona | Department | Frequency | Dependencies |
|---|---------|-----------|-----------|-------------|
| P1 | Threat Intelligence Researcher | Research | Weekly (Mon) | → P8, P9, P10, P11, P20 |
| P2 | Ecosystem Cartographer | Research | Weekly (Tue) | → P5, P6, P12, P15, P20 |
| P3 | Competitive Intelligence | Research | Bi-weekly | → P12, P15, P16 |
| P4 | Registry Architect | Engineering | 2x/week | → P5, P6, P7, P12 |
| P5 | Crawler Engineer | Engineering | Daily | → P6, P4 |
| P6 | Data Engineer | Engineering | Daily | → P4, P9, P13 |
| P7 | Infrastructure Engineer | Engineering | As needed | → P4, P5, P6 |
| P8 | Detection Rule Engineer | Security | 2x/week | → P9, P4 |
| P9 | Scanner Engine Engineer | Security | Daily | → P6, P13, P14 |
| P10 | Adversarial Tester | Security | Bi-weekly | → P8, P9, P1 |
| P11 | Compliance Mapper | Security | Monthly | → P8, P9, P20 |
| P12 | Product Strategist | Product | 2x/week | ← All departments |
| P13 | Registry UX Designer | Product | Daily→Weekly | → P4, P6, P14 |
| P14 | API & DevEx Engineer | Product | Bi-weekly | → P4, P12 |
| P15 | Growth Engineer | Growth | Weekly (Fri) | → P12, P13 |
| P16 | Fundraise Advisor | Growth | Bi-weekly | → P12, P3, P15 |
| P17 | Partnerships Strategist | Growth | Monthly | → P2, P3, P12 |
| P18 | Trust & Accuracy Auditor | Quality | Weekly | → P9, P10, P6 |
| P19 | Legal & Ethics Advisor | Quality | Monthly | → P18, P12 |
| P20 | Report Author | Quality | Monthly | ← All departments |

### Execution Order for First Build

**Week 1:** P4 → P5 → P6 → P8 → P12
**Week 2:** P1 → P2 → P9 → P13 → P7
**Week 3-4:** P10 → P14 → P15 → P18 → P19
**Week 5-6:** P3 → P11 → P17 → P16 → P20

### Data Flow Between Personas

```
P1 (Threats) ──→ P8 (Rules) ──→ P9 (Scanner) ──→ P18 (Audit)
P2 (Ecosystem) ──→ P5 (Crawler) ──→ P6 (Data) ──→ P13 (UX)
P3 (Competitors) ──→ P12 (Product) ──→ P15 (Growth)
P10 (Red Team) ──→ P8 (Rules) [feedback loop]
P11 (Compliance) + P20 (Report) ← All departments
```
