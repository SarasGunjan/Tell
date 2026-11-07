# Tell Platform — Team Workflow & Interface Contracts

**Team:** 3-Person Parallel Development Architecture  
**Platform Name:** Tell  
**Datathon Track:** IBM Before the Breach (Sheridan Datathon 2026)

---

## 1. Team Division & Responsibilities

```
┌─────────────────────────────────┬─────────────────────────────────┬─────────────────────────────────┐
│ Member 1: Data Science & ML     │ Member 2: IBM Granite & Research│ Member 3: Full-Stack & Cloud    │
├─────────────────────────────────┼─────────────────────────────────┼─────────────────────────────────┤
│ • Time-safe cohort builder      │ • Granite feature extraction    │ • Streamlit enterprise dashboard│
│ • Historical 2024 & 2025 sets   │ • Semantic exploit clustering   │ • Snowflake Cortex REST API     │
│ • CVSS & EPSS baselines         │ • Behavioral family profiling   │ • Google Gemini structured briefs│
│ • Logistic Regression & LightGBM│ • Attacker preference research  │ • Evidence grounding checks     │
│ • Zero-leakage enforcement      │ • Description embeddings        │ • Vultr Cloud Compute deployment│
│ • Final Top 500 ranking export  │ • Quantified research findings  │ • Secure credentials & Docker   │
└─────────────────────────────────┴─────────────────────────────────┴─────────────────────────────────┘
```

---

## 2. Agreed File Contracts

To enable instantaneous parallel execution without blocking dependencies, the team established strict file contracts:

| File Name | Producer | Consumer | Required Columns | Verified Status |
| :--- | :--- | :--- | :--- | :--- |
| `results/predictions.csv` | Member 1 | Member 3 | `cve_id`, `rank`, `prediction_score`, `epss` | **VERIFIED (72,670 rows)** |
| `results/top500.csv` | Member 1 | Submission / Member 3 | `cve_id` (single column, exactly 500 rows) | **VERIFIED (500 rows)** |
| `results/metrics.csv` | Member 1 | Member 3 | `model`, `hits_100`, `hits_250`, `hits_500` | **VERIFIED (6 models)** |
| `results/granite_features.csv` | Member 2 | Member 3 | `cve_id`, `family_id`, `remote_local`, `auth_required` | **VERIFIED (72,670 rows)** |
| `results/family_summary.csv` | Member 2 | Member 3 | `family_id`, `family_name`, `family_size` | **VERIFIED (10 families)** |
| `results/families.csv` | Member 2 | Member 3 | `cve_id`, `family_id`, `family_name`, `attack_type` | **VERIFIED (72,670 rows)** |

---

## 3. Git Branching Model

```
master / main (Integrated Tell Platform)
  ▲
  ├─ Pull Request: feature/data-ml (Member 1 - Data Science & Predictions)
  ├─ Pull Request: feature/granite (Member 2 - IBM Granite & Exploit Families)
  └─ Pull Request: feature/dashboard (Member 3 - Streamlit UI, APIs & Vultr Deployment)
```

Each member developed in isolated modules with clean unit tests before final integration.
